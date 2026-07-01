#!/usr/bin/env python3
"""Audit rel32 CALL/JMP targets in translated cmd_shim vs x86 source + rva_map.

Flags:
  - OUT_OF_TEXT      target outside .text
  - INT3_GAP         target lands on 0xCC padding
  - MID_INSN         target is not a Capstone instruction boundary
  - MID_FUNCTION     target is in a translated function but not at fn entry
  - BAD_PROLOGUE     target lacks any recognizable function prologue nearby
  - RVA_MAP_DRIFT    rva_map[old_rva] != nearest fn entry for that function

Usage:
  python scan_call_targets.py [cmd_shim.exe] [--rebuild] [--limit N]
"""
from __future__ import annotations

import argparse
import os
import struct
import sys
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

from capstone import Cs, CS_ARCH_X86, CS_MODE_64

ROOT = os.path.dirname(os.path.abspath(__file__))
DEFAULT_SHIM = os.path.join(ROOT, "..", "win2000_x64", "cmd_shim.exe")
DEFAULT_X86 = (
    r"C:\Users\win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU\cmd.exe"
)

PROLOGUES = (
    b"\x55\x48\x89",       # push rbp; mov rbp,rsp
    b"\x48\x83\xec",       # sub rsp, N
    b"\x53",               # push rbx
    b"\x56",               # push rsi
    b"\x41\x55",           # push r13
    b"\x48\x89\xf1",       # mov rcx,rsi (import wrapper)
    b"\x49\x89\xca",       # mov r10,rcx (cmd fn6314 patched)
)


@dataclass
class Finding:
    kind: str
    call_rva: int
    tgt_rva: int
    detail: str = ""
    x86_hint: str = ""


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


def insn_starts(text: bytes, text_rva: int, base: int) -> Set[int]:
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    return {ins.address - base for ins in md.disasm(text, base + text_rva)}


def fn_entry_before(text: bytes, tgt_off: int, max_back: int = 128) -> Optional[int]:
    """Best-effort blob offset of enclosing function prologue."""
    lo = max(0, tgt_off - max_back)
    best = None
    for off in range(tgt_off, lo - 1, -1):
        for pro in PROLOGUES:
            if text[off : off + len(pro)] == pro:
                if off <= tgt_off:
                    best = off
                break
    return best


def build_fn_entries(rva_map: Dict[int, int]) -> Set[int]:
    return {off for off in rva_map.values() if off is not None}


def rebuild_rva_map(x86_path: str):
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
    return tr.rva_map, tr._fn_entry_rvas, pe


def audit(shim_path: str, x86_path: str, rebuild: bool, limit: int) -> List[Finding]:
    text, text_rva, base = load_text(shim_path)
    starts = insn_starts(text, text_rva, base)
    rva_map: Dict[int, int] = {}
    fn_entry_rvas: Set[int] = set()
    if rebuild and os.path.isfile(x86_path):
        rva_map, fn_entry_rvas, _pe = rebuild_rva_map(x86_path)
    fn_entries = build_fn_entries(rva_map)

    findings: List[Finding] = []
    drift: List[Tuple[int, int, int]] = []

    # rva_map entries that land mid-function vs their prologue
    for old_rva, off in sorted(rva_map.items()):
        if off is None or off in fn_entries:
            continue
        entry = fn_entry_before(text, off)
        if entry is not None and entry != off and off - entry < 0x200:
            drift.append((old_rva, off, entry))

    md = Cs(CS_ARCH_X86, CS_MODE_64)
    for i in range(len(text) - 5):
        if text[i] != 0xE8:
            continue
        rel = struct.unpack_from("<i", text, i + 1)[0]
        call_rva = text_rva + i
        tgt_rva = text_rva + i + 5 + rel
        tgt_off = tgt_rva - text_rva
        if tgt_off < 0 or tgt_off >= len(text):
            findings.append(Finding("OUT_OF_TEXT", call_rva, tgt_rva))
            continue
        if text[tgt_off] == 0xCC:
            findings.append(Finding("INT3_GAP", call_rva, tgt_rva))
            continue
        if tgt_rva not in starts:
            entry = fn_entry_before(text, tgt_off)
            entry_rva = text_rva + entry if entry is not None else None
            detail = f"insn_start miss; prologue~0x{entry_rva:x}" if entry_rva else "no prologue"
            findings.append(Finding("MID_INSN", call_rva, tgt_rva, detail))
            continue
        if tgt_off not in fn_entries:
            entry = fn_entry_before(text, tgt_off)
            if entry is not None and entry != tgt_off:
                findings.append(
                    Finding(
                        "MID_FUNCTION",
                        call_rva,
                        tgt_rva,
                        f"fn_entry~0x{text_rva + entry:x} (+0x{tgt_off - entry:x})",
                    )
                )
            elif text[tgt_off : tgt_off + 3] not in PROLOGUES[:3]:
                # align-prologue interior (push r13 at +1 from 41 55 ...)
                if not (text[tgt_off] == 0x49 and text[tgt_off + 1 : tgt_off + 3] == b"\x89\xe5"):
                    findings.append(Finding("BAD_PROLOGUE", call_rva, tgt_rva))

    # attach x86 hints for high-value sites
    if rva_map:
        off_to_old: Dict[int, int] = {}
        for old, off in rva_map.items():
            if off is not None:
                off_to_old[off] = old
        for f in findings:
            call_off = f.call_rva - text_rva
            candidates = [(o, off) for off, o in off_to_old.items() if abs(off - call_off) < 0x40]
            if candidates:
                old, _ = max(candidates, key=lambda x: x[1])
                f.x86_hint = f"x86 call site ~0x{old:X}"

    findings.sort(key=lambda f: (f.kind, f.call_rva))
    return findings[:limit], drift[:20]


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("shim", nargs="?", default=DEFAULT_SHIM)
    ap.add_argument("--x86", default=DEFAULT_X86)
    ap.add_argument("--rebuild", action="store_true",
                    help="Run translator to build rva_map (slow, ~90s)")
    ap.add_argument("--limit", type=int, default=40)
    args = ap.parse_args()

    if not os.path.isfile(args.shim):
        print("missing shim:", args.shim)
        raise SystemExit(1)

    findings, drift = audit(args.shim, args.x86, args.rebuild, args.limit)
    kinds: Dict[str, int] = {}
    for f in findings:
        kinds[f.kind] = kinds.get(f.kind, 0) + 1

    print(f"\n=== call target audit: {args.shim} ===")
    for k, n in sorted(kinds.items(), key=lambda x: -x[1]):
        print(f"  {k:16} {n}")
    print(f"\nTop findings (limit {args.limit}):")
    for f in findings:
        line = f"  [{f.kind}] call 0x{f.call_rva:X} -> 0x{f.tgt_rva:X}  {f.detail}"
        if f.x86_hint:
            line += f"  ({f.x86_hint})"
        print(line)

    if drift:
        print("\nrva_map drift (entry should be prologue, not mid-fn):")
        for old, off, entry in drift[:12]:
            print(f"  x86 0x{old:X} mapped to blob+0x{off:X}, prologue at +0x{entry:X}")


if __name__ == "__main__":
    main()
