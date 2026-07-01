#!/usr/bin/env python3
"""Static + optional runtime diagnosis for cmd_shim startup crashes.

Explains *what* is wrong, *why* it matters, and the likely *x86 origin* when
``--rebuild`` is used to obtain ``rva_map``.

Usage:
  python diagnose_startup.py [cmd_shim.exe]
  python diagnose_startup.py --rebuild
  python diagnose_startup.py --run /c echo test
"""
from __future__ import annotations

import argparse
import os
import struct
import subprocess
import sys
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

ROOT = os.path.dirname(os.path.abspath(__file__))
DEFAULT_SHIM = os.path.join(ROOT, "..", "win2000_x64", "cmd_shim.exe")
DEFAULT_X86 = (
    r"C:\Users\win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU\cmd.exe"
)
INIT_TAIL_LO = 0x3FD50
INIT_TAIL_HI = 0x3FE20
ENTRY_SEH_BLOB_OFF = 0x8777  # shim .text RVA of CRT entry SEH prologue


@dataclass
class Issue:
    severity: int  # 1=critical, 5=info
    code: str
    summary: str
    detail: str = ""
    x86_origin: str = ""
    fix_hint: str = ""


def load_text(path: str) -> Tuple[bytes, int, int]:
    data = open(path, "rb").read()
    pe = struct.unpack_from("<I", data, 0x3C)[0]
    opt = pe + 24
    opt_sz = struct.unpack_from("<H", data, pe + 20)[0]
    base = struct.unpack_from("<Q", data, opt + 24)[0]
    n = struct.unpack_from("<H", data, pe + 6)[0]
    sec_off = pe + 24 + opt_sz
    for i in range(n):
        o = sec_off + i * 40
        if data[o : o + 5] != b".text":
            continue
        vs, va, rawsz, rawptr = struct.unpack_from("<IIII", data, o + 8)
        return data[rawptr : rawptr + rawsz], va, base
    raise SystemExit(f"no .text in {path}")


def rebuild_rva_map(x86_path: str) -> Tuple[Dict[int, int], Set[int]]:
    sys.path.insert(0, ROOT)
    from x86_x64 import DynamicScanResult, PE32Image, Win2000Translator

    pe = PE32Image(open(x86_path, "rb").read())
    tr = Win2000Translator(
        pe,
        DynamicScanResult(),
        verbose=False,
        win10_test_shim=True,
        source_path=x86_path,
    )
    tr.translate()
    return tr.rva_map, tr._fn_entry_rvas or set()


def blob_off_for_va(base: int, text_rva: int, va: int) -> Optional[int]:
    if not (base <= va < base + 0x01000000):
        return None
    off = va - base - text_rva
    return off if off >= 0 else None


def valid_scope_sentinel(text: bytes, off: int, base: int, img_size: int = 0x500000) -> bool:
    if off + 12 > len(text) or text[off : off + 4] != b"\xff\xff\xff\xff":
        return False
    begin, end_va = struct.unpack_from("<II", text, off + 4)
    old_base = 0x4AD00000
    img_end = old_base + img_size
    shim_end = base + 0x01000000
    x86_ok = old_base <= begin < img_end and old_base < end_va <= img_end
    shim_ok = base <= begin < shim_end and base < end_va <= shim_end
    if not ((x86_ok or shim_ok) and begin < end_va):
        return False
    return (end_va - begin) >= 0x10


def x86_hint_for_blob(
    blob_off: int, rva_map: Dict[int, int], window: int = 0x60
) -> str:
    if not rva_map:
        return ""
    best_old = None
    best_dist = window + 1
    for old, off in rva_map.items():
        if off is None:
            continue
        d = abs(off - blob_off)
        if d < best_dist:
            best_dist = d
            best_old = old
    if best_old is None:
        return ""
    return f"x86 ~0x{best_old:X} (blob+0x{blob_off:X}, Δ{best_dist})"


def scan_seh_scope_pushes(
    text: bytes, text_rva: int, base: int, rva_map: Dict[int, int]
) -> List[Issue]:
    issues: List[Issue] = []
    bad_lo = base + INIT_TAIL_LO
    bad_hi = base + INIT_TAIL_HI
    bad_sites: List[Tuple[int, int]] = []

    for i in range(len(text) - 14):
        if not (
            text[i] == 0x6A
            and text[i + 1] == 0xFF
            and text[i + 2] == 0x48
            and text[i + 3] == 0xB8
        ):
            continue
        imm = struct.unpack_from("<Q", text, i + 4)[0]
        site_rva = text_rva + i
        tgt_off = blob_off_for_va(base, text_rva, imm)
        if tgt_off is None:
            issues.append(
                Issue(
                    2,
                    "SEH_SCOPE_OOR",
                    f"SEH push at 0x{site_rva:X} points outside image",
                    f"movabs imm=0x{imm:X}",
                    x86_hint_for_blob(i, rva_map),
                    "Reconcile scope push to materialized ff ff ff ff blob",
                )
            )
            continue
        if bad_lo <= imm <= bad_hi:
            bad_sites.append((site_rva, imm))
            if not valid_scope_sentinel(text, tgt_off, base):
                sentinel = text[tgt_off : tgt_off + 4].hex()
                issues.append(
                    Issue(
                        1,
                        "SEH_INIT_TAIL",
                        f"SEH scope at 0x{site_rva:X} -> init-tail 0x{imm:X} (not a scope table)",
                        f"target blob+0x{tgt_off:X} bytes={sentinel} (expect ffffffff)",
                        x86_hint_for_blob(i, rva_map),
                        "_restore_materialized_scope_tables after init-tail neutralization",
                    )
                )
        elif not valid_scope_sentinel(text, tgt_off, base):
            issues.append(
                Issue(
                    2,
                    "SEH_BAD_SENTINEL",
                    f"SEH scope at 0x{site_rva:X} lacks valid ff ff ff ff record",
                    f"target 0x{imm:X} blob+0x{tgt_off:X}",
                    x86_hint_for_blob(i, rva_map),
                    "_reconcile_seh_scope_pushes",
                )
            )

    entry_off = ENTRY_SEH_BLOB_OFF - text_rva
    if 0 <= entry_off < len(text) - 14:
        if (
            text[entry_off] == 0x6A
            and text[entry_off + 1] == 0xFF
            and text[entry_off + 2] == 0x48
            and text[entry_off + 3] == 0xB8
        ):
            imm = struct.unpack_from("<Q", text, entry_off + 4)[0]
            tgt_off = blob_off_for_va(base, text_rva, imm)
            ok = tgt_off is not None and valid_scope_sentinel(text, tgt_off, base)
            if not ok:
                issues.insert(
                    0,
                    Issue(
                        1,
                        "ENTRY_SEH",
                        "CRT entry SEH scope still broken (startup will corrupt stack)",
                        f"main+0x{ENTRY_SEH_BLOB_OFF:X} imm=0x{imm:X}",
                        "x86 CRT entry / WinMain SEH wrapper",
                        "Rebuild after scope_blob size fix (20-byte record, not 36)",
                    ),
                )
            else:
                issues.append(
                    Issue(
                        5,
                        "ENTRY_SEH_OK",
                        "CRT entry SEH scope looks valid",
                        f"points to 0x{imm:X}",
                    )
                )

    if len(bad_sites) >= 3:
        issues.append(
            Issue(
                1,
                "SEH_CLUSTER",
                f"{len(bad_sites)} SEH sites share init-tail NOP sled targets",
                "All point into 0x8003FD50–0x8003FE20 stub region",
                "x86 scope tables materialized into wrong blob offsets during translate",
                "Shared scope table inject at safe tail slot",
            )
        )
    return issues


def scan_init_tail_calls(text: bytes, text_rva: int, base: int) -> List[Issue]:
    issues: List[Issue] = []
    tail_lo = INIT_TAIL_LO - text_rva
    tail_hi = INIT_TAIL_HI - text_rva
    if tail_lo < 0:
        tail_lo = 0
    for i in range(len(text) - 5):
        if text[i] != 0xE8:
            continue
        rel = struct.unpack_from("<i", text, i + 1)[0]
        tgt_off = i + 5 + rel
        if tail_lo <= tgt_off < tail_hi:
            tgt_rva = text_rva + tgt_off
            insn = text[tgt_off : tgt_off + 4]
            kind = "stub"
            if insn[:2] == b"\x31\xc0":
                kind = "xor eax,eax; ret stub"
            elif insn[0] == 0x90:
                kind = "NOP sled interior"
            issues.append(
                Issue(
                    2,
                    "CALL_INIT_TAIL",
                    f"call 0x{text_rva + i:X} -> init-tail 0x{tgt_rva:X}",
                    kind,
                    "",
                    "Neutralize _initterm stubs or snap call to stub entry",
                )
            )
    return issues


def scan_bad_movabs_in_tail(text: bytes, text_rva: int, base: int) -> List[Issue]:
    issues: List[Issue] = []
    bad_lo = base + INIT_TAIL_LO
    bad_hi = base + INIT_TAIL_HI
    n = 0
    for i in range(len(text) - 10):
        if text[i : i + 2] != b"\x48\xb8":
            continue
        imm = struct.unpack_from("<Q", text, i + 2)[0]
        if bad_lo <= imm <= bad_hi:
            n += 1
    if n:
        issues.append(
            Issue(
                1 if n >= 5 else 2,
                "MOVABS_INIT_TAIL",
                f"{n} movabs immediates still target init-tail region",
                f"VA range 0x{bad_lo:X}–0x{bad_hi:X}",
                "",
                "Post-patch entry SEH scope injects (should be 0 after rebuild)",
            )
        )
    return issues


def diagnose(
    shim_path: str,
    x86_path: str,
    rebuild: bool,
) -> Tuple[List[Issue], Dict[int, int]]:
    text, text_rva, base = load_text(shim_path)
    rva_map: Dict[int, int] = {}
    if rebuild and os.path.isfile(x86_path):
        print(f"[diagnose] rebuilding rva_map from {x86_path} …")
        rva_map, _ = rebuild_rva_map(x86_path)

    issues: List[Issue] = []
    issues.extend(scan_seh_scope_pushes(text, text_rva, base, rva_map))
    issues.extend(scan_init_tail_calls(text, text_rva, base))
    issues.extend(scan_bad_movabs_in_tail(text, text_rva, base))

    issues.sort(key=lambda x: (x.severity, x.code))
    return issues, rva_map


def print_report(shim_path: str, issues: List[Issue]) -> None:
    crit = [i for i in issues if i.severity <= 2]
    print(f"\n{'=' * 72}")
    print(f" STARTUP DIAGNOSIS: {shim_path}")
    print(f"{'=' * 72}")
    if not crit:
        print("\n  No critical startup issues detected statically.")
        print("  If runtime still fails, run: python diagnose_startup.py --run")
    else:
        print(f"\n  {len(crit)} issue(s) likely blocking startup (severity 1–2):\n")
        for n, iss in enumerate(crit, 1):
            print(f"  [{n}] {iss.code}: {iss.summary}")
            if iss.detail:
                print(f"       detail : {iss.detail}")
            if iss.x86_origin:
                print(f"       x86    : {iss.x86_origin}")
            elif iss.code.startswith("SEH") or iss.code == "ENTRY_SEH":
                print(f"       x86    : (use --rebuild for origin hints)")
            if iss.fix_hint:
                print(f"       fix    : {iss.fix_hint}")
            print()

    info = [i for i in issues if i.severity >= 5]
    for iss in info:
        print(f"  OK: {iss.summary}")

    print(f"\n{'=' * 72}")
    if any(i.code == "ENTRY_SEH" for i in crit):
        print(" VERDICT: Fix entry SEH scope table, rebuild, re-run echo test")
    elif any(i.code == "SEH_INIT_TAIL" for i in crit):
        print(" VERDICT: Materialize SEH scope tables (init-tail pointers are NOPs)")
    elif any(i.code == "CALL_INIT_TAIL" for i in crit):
        print(" VERDICT: Calls landing in init-tail stubs — fix _initterm neutralization")
    elif crit:
        print(" VERDICT: See issues above; rebuild shim after translator fixes")
    else:
        print(" VERDICT: Static checks passed — try runtime with --run")
    print(f"{'=' * 72}\n")


def run_runtime(shim_path: str, run_args: List[str]) -> int:
    import dbg_fault as df

    df.suppress_fault_ui()
    dbg = os.path.join(ROOT, "dbg_root.py")
    cmd = [sys.executable, dbg, shim_path] + run_args
    print(f"[diagnose] runtime: {' '.join(cmd)}\n")
    return subprocess.call(cmd)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("shim", nargs="?", default=DEFAULT_SHIM)
    ap.add_argument("--x86", default=DEFAULT_X86)
    ap.add_argument("--rebuild", action="store_true")
    ap.add_argument(
        "--run",
        nargs=argparse.REMAINDER,
        help="Run dbg_root.py on shim with args (e.g. --run /c echo test)",
    )
    args = ap.parse_args()
    shim = os.path.abspath(args.shim)
    if not os.path.isfile(shim):
        print("missing shim:", shim)
        return 1

    issues, _ = diagnose(shim, args.x86, args.rebuild)
    print_report(shim, issues)

    if args.run is not None:
        run_args = args.run
        if run_args and run_args[0] == "--":
            run_args = run_args[1:]
        if not run_args:
            run_args = ["/c", "echo", "test"]
        return run_runtime(shim, run_args)
    return 0 if not any(i.severity <= 2 for i in issues) else 1


if __name__ == "__main__":
    sys.exit(main())
