#!/usr/bin/env python3
"""
Measure how far each translated build actually gets before it faults.

Byte-identical output only proves a change was inert. The question that
matters is how many instructions the image executes and where it dies, so
this runs the step-over tracer over a corpus of builds and tabulates the
answer. Results are cached, so widening or re-running a sweep is cheap.

A build that the loader refuses can optionally be healed in a scratch copy
(``--heal-gap``) by folding reserved inter-section space back into the
preceding section's VirtualSize. That separates "won't load" from "loads but
misbehaves" -- two failures that otherwise look identical from outside.

    python tools/regress.py --sample 20            # coarse sweep
    python tools/regress.py --builds 110-120       # bisect a drop
    python tools/regress.py --builds 225 --heal-gap
"""

from __future__ import annotations

import argparse
import json
import pathlib
import re
import shutil
import struct
import subprocess
import sys
import tempfile
from typing import Dict, List, Optional

REPO = pathlib.Path(__file__).resolve().parent.parent
CACHE = REPO / '.regress_cache.json'
STEPS_RE = re.compile(r'steps=(\d+)')
FAULT_RE = re.compile(r'code=(0x[0-9A-Fa-f]+)\s+RIP=(0x[0-9A-Fa-f]+)')
ACCESS_RE = re.compile(r'access-violation: (\w+) @ (0x[0-9A-Fa-f]+)')

FAULT_NAMES = {
    0xC0000005: 'AV',
    0xC00000FD: 'STACK_OVF',
    0xC000001D: 'BAD_INSN',
    0xC0000025: 'NONCONT_EXC',
    0xC0000096: 'PRIV_INSN',
    0xC0000135: 'DLL_MISSING',
    0xC0000142: 'DLL_INIT_FAIL',
    0xC0000409: 'STACK_CHECK',
}


def heal_section_gaps(blob: bytes) -> tuple:
    """Grow each section's VirtualSize to meet the next section's RVA.

    Returns ``(healed_bytes, closed)`` where ``closed`` counts the holes
    removed. Reserved space between sections is legal to the translator but
    fatal to the loader; folding it into the previous section changes nothing
    about what is mapped where.
    """
    data = bytearray(blob)
    pe = struct.unpack_from('<I', data, 0x3C)[0]
    n = struct.unpack_from('<H', data, pe + 6)[0]
    opt_sz = struct.unpack_from('<H', data, pe + 20)[0]
    align_ = struct.unpack_from('<I', data, pe + 24 + 32)[0] or 0x1000
    sec = pe + 24 + opt_sz

    headers = []
    for i in range(n):
        off = sec + i * 40
        vsize, vaddr = struct.unpack_from('<II', data, off + 8)
        headers.append((off, vsize, vaddr))
    rvas = sorted(h[2] for h in headers)

    closed = 0
    for off, vsize, vaddr in headers:
        nxt = next((r for r in rvas if r > vaddr), 0)
        end = (vaddr + vsize + align_ - 1) & ~(align_ - 1)
        if nxt and nxt > end:
            struct.pack_into('<I', data, off + 8, nxt - vaddr)
            closed += 1
    return bytes(data), closed


def _materialize(exe: pathlib.Path, heal: bool) -> tuple:
    """Return ``(path_to_run, tempdir_or_None, result_stub)``.

    When healing is on and the image has holes, the runnable copy lives in a
    scratch directory next to the shim DLL so the original is left untouched.
    """
    sys.path.insert(0, str(REPO))
    from x86x64.pe import validate_pe

    blob = exe.read_bytes()
    report = validate_pe(blob)
    result: Dict[str, object] = {
        'valid': report.ok,
        'errors': [f.code for f in report.errors],
        'healed': 0,
    }

    if not (heal and not report.ok):
        return exe, None, result

    healed, closed = heal_section_gaps(blob)
    if not closed:
        return exe, None, result

    tmp = pathlib.Path(tempfile.mkdtemp(prefix='regress_'))
    target = tmp / exe.name
    target.write_bytes(healed)
    shim = exe.parent / 'w2kshim64.dll'
    if shim.exists():
        shutil.copy2(shim, tmp / shim.name)
    result['healed'] = closed
    return target, tmp, result


def run_echo(exe: pathlib.Path, *, heal: bool, text: str,
             seconds: int) -> Dict[str, object]:
    """Run ``<exe> /c echo <text>`` and report whether the text came back.

    This is the only measurement that says the translation is correct rather
    than merely surviving: the image has to reach the command parser, run a
    builtin, write to a handle it inherited, and exit cleanly.
    """
    target, tmp, result = _materialize(exe, heal)
    flags = getattr(subprocess, 'CREATE_NO_WINDOW', 0)
    try:
        proc = subprocess.run([str(target), '/c', 'echo', text],
                              capture_output=True, timeout=seconds,
                              cwd=str(target.parent), creationflags=flags)
        code = proc.returncode & 0xFFFFFFFF
        out = proc.stdout or b''
        decoded = out.decode('utf-16-le', 'replace') + out.decode('latin1', 'replace')
        result['exit'] = f'0x{code:08X}'
        result['bytes'] = len(out)
        if code == 0 and text in decoded:
            result['status'] = 'ECHO OK'
        elif code == 0:
            result['status'] = 'silent'
        else:
            result['status'] = FAULT_NAMES.get(code, 'exit')
    except subprocess.TimeoutExpired:
        result['status'] = 'HANG'
    except OSError as exc:
        result['status'] = 'REJECTED'
        result['exit'] = str(getattr(exc, 'winerror', exc))
    finally:
        if tmp:
            shutil.rmtree(tmp, ignore_errors=True)
    return result


def run_one(exe: pathlib.Path, *, heal: bool, seconds: int) -> Dict[str, object]:
    """Trace one image and summarise where it stopped."""
    target, tmp, result = _materialize(exe, heal)

    try:
        proc = subprocess.run(
            [sys.executable, str(REPO / 'dbg_trace.py'), str(target),
             '--ring=6', f'--seconds={seconds}'],
            capture_output=True, text=True, timeout=seconds + 40,
            cwd=str(REPO), errors='replace')
        out = (proc.stdout or '') + (proc.stderr or '')
    except subprocess.TimeoutExpired:
        out = '<timeout>'
    finally:
        if tmp:
            shutil.rmtree(tmp, ignore_errors=True)

    if 'CreateProcess failed' in out:
        result['status'] = 'REJECTED'
        return result

    steps = STEPS_RE.search(out)
    fault = FAULT_RE.search(out)
    access = ACCESS_RE.search(out)
    result['steps'] = int(steps.group(1)) if steps else 0
    if fault:
        result['status'] = 'FAULT'
        result['code'] = fault.group(1)
        result['rip'] = fault.group(2)
    elif '<timeout>' in out:
        result['status'] = 'TIMEOUT'
    else:
        result['status'] = 'RAN'
    if access:
        result['access'] = f'{access.group(1)} @ {access.group(2)}'
    return result


def build_numbers() -> List[int]:
    nums = []
    for d in REPO.glob('build_out*'):
        if (d / 'cmd_pure.exe').exists():
            digits = re.sub(r'\D', '', d.name)
            if digits:
                nums.append(int(digits))
    return sorted(nums)


def parse_selection(spec: Optional[str], sample: Optional[int]) -> List[int]:
    every = build_numbers()
    if spec:
        picked = set()
        for part in spec.split(','):
            if '-' in part:
                lo, hi = part.split('-')
                picked |= {n for n in every if int(lo) <= n <= int(hi)}
            else:
                picked.add(int(part))
        return sorted(picked & set(every))
    if sample:
        step = max(1, len(every) // sample)
        chosen = every[::step]
        if every[-1] not in chosen:
            chosen.append(every[-1])
        return chosen
    return every


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--builds', help='e.g. 110-120 or 112,150,225')
    ap.add_argument('--sample', type=int, help='spread N probes over the corpus')
    ap.add_argument('--heal-gap', action='store_true',
                    help='close section holes in a scratch copy before running')
    ap.add_argument('--seconds', type=int, default=25)
    ap.add_argument('--refresh', action='store_true', help='ignore cached results')
    ap.add_argument('--echo', action='store_true',
                    help='run "/c echo" for a pass/fail answer instead of tracing')
    ap.add_argument('--text', default='w2ktest', help='string to echo')
    args = ap.parse_args()

    cache = json.loads(CACHE.read_text()) if CACHE.exists() else {}
    targets = parse_selection(args.builds, args.sample)
    if not targets:
        print('no builds selected')
        return 1

    sys.path.insert(0, str(REPO))
    try:
        import dbg_fault
        dbg_fault.suppress_fault_ui()
    except Exception:
        pass

    mode = 'echo' if args.echo else 'trace'
    seconds = args.seconds if not args.echo else min(args.seconds, 20)
    if args.echo:
        print(f'{"build":>7} {"status":<14} {"exit":<12} {"out":>7}  notes')
    else:
        print(f'{"build":>7} {"status":<14} {"steps":>9} {"fault":<20} notes')
    print('-' * 74)

    passing = 0
    for num in targets:
        key = f'{num}:{int(args.heal_gap)}:{mode}'
        if args.refresh or key not in cache:
            exe = REPO / f'build_out{num}' / 'cmd_pure.exe'
            cache[key] = (run_echo(exe, heal=args.heal_gap, text=args.text,
                                   seconds=seconds) if args.echo else
                          run_one(exe, heal=args.heal_gap, seconds=seconds))
            CACHE.write_text(json.dumps(cache, indent=1))
        r = cache[key]
        notes = []
        if r.get('healed'):
            notes.append(f'healed {r["healed"]} gap(s)')
        if r.get('errors'):
            notes.append(','.join(r['errors']))
        if args.echo:
            if r['status'] == 'ECHO OK':
                passing += 1
            print(f'{num:>7} {r["status"]:<14} {str(r.get("exit","")):<12} '
                  f'{r.get("bytes", 0):>7}  {" ".join(notes)}')
        else:
            fault = r.get('access') or r.get('rip', '')
            print(f'{num:>7} {r["status"]:<14} {r.get("steps", 0):>9,} '
                  f'{str(fault):<20} {" ".join(notes)}')

    if args.echo:
        print('-' * 74)
        print(f'{passing}/{len(targets)} builds echoed correctly')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
