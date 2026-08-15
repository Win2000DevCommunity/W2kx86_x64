"""Offline probe: restore shredded cmp/jcc + align self-call on interactive path.

Universal heals land in translator; this applies the same site-level repairs on
univ258/cmd_probe_wfs.exe so we can smoke interactive before univ259 finishes.
"""
from __future__ import annotations

import pathlib
import struct
import subprocess
import sys
import time

import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64


def _text_blob(pe_bytes: bytearray) -> tuple[int, int, int, bytearray]:
    e = struct.unpack_from("<I", pe_bytes, 0x3C)[0]
    ns = struct.unpack_from("<H", pe_bytes, e + 6)[0]
    so = struct.unpack_from("<H", pe_bytes, e + 20)[0]
    sec = e + 24 + so
    for i in range(ns):
        o = sec + i * 40
        if pe_bytes[o:o + 5] == b".text":
            vs, va, rs, rp = struct.unpack_from("<IIII", pe_bytes, o + 8)
            return va, rp, rs, bytearray(pe_bytes[rp:rp + rs])
    raise RuntimeError(".text not found")


def _write_text(pe_bytes: bytearray, rp: int, blob: bytes) -> None:
    pe_bytes[rp:rp + len(blob)] = blob


def _fix_zeroed_jcc_after_cmp(blob: bytearray, text_va: int) -> int:
    """Restore ``cmp …; 0F 00 00 00 00 00`` when skip lands on success+fail epi.

    Pattern (MSVC shared cleanup): after the placeholder, a nearby
    ``mov eax,esi; pop rsi; ret`` precedes the fail/helper body.  x86
    ``jne`` to ``call helper`` becomes a jump to that helper body.
    Condition is taken from the twin short/near jcc when the preceding
    cmp is ``cmp r16/r32, imm`` (default ``jne`` — the common skip form).
    """
    fixed = 0
    n = len(blob)
    i = 0
    while i + 10 < n:
        # 66 83 /7 ib  or  83 /7 ib  immediately before placeholder
        pre = None
        if (i >= 4 and blob[i:i + 6] == b"\x0f\x00\x00\x00\x00\x00"
                and blob[i - 4] == 0x66 and blob[i - 3] == 0x83
                and (blob[i - 2] & 0xF8) == 0xF8):
            pre = i - 4
        elif (i >= 3 and blob[i:i + 6] == b"\x0f\x00\x00\x00\x00\x00"
              and blob[i - 3] == 0x83 and (blob[i - 2] & 0xF8) == 0xF8):
            pre = i - 3
        if pre is None:
            i += 1
            continue
        # Look ahead for mov eax,esi; pop rsi; ret then helper body
        tgt = None
        for j in range(i + 6, min(n - 4, i + 0x200)):
            if blob[j:j + 4] == bytes.fromhex("89f05ec3"):
                tgt = j + 4
                break
        if tgt is None:
            i += 1
            continue
        # Default jne (0x85) — matches x86 skip-to-helper after cmp imm
        blob[i + 1] = 0x85
        struct.pack_into("<i", blob, i + 2, tgt - (i + 6))
        fixed += 1
        i += 6
    return fixed


def _fix_je_to_success_epi(blob: bytearray) -> int:
    """``je`` that overshoots ``mov eax,esi; pop rsi; ret`` onto the next body."""
    fixed = 0
    n = len(blob)
    epi = bytes.fromhex("89f05ec3")
    for i in range(n - 10):
        if blob[i] != 0x0F or blob[i + 1] != 0x84:
            continue
        rel = struct.unpack_from("<i", blob, i + 2)[0]
        cur = i + 6 + rel
        if not (0 <= cur < n):
            continue
        # Success epi within 8 bytes before the current target (nop padding).
        new_tgt = None
        for back in range(1, 9):
            s = cur - back
            if s >= 0 and blob[s:s + 4] == epi:
                new_tgt = s
                break
        if new_tgt is None or new_tgt == cur:
            continue
        struct.pack_into("<i", blob, i + 2, new_tgt - (i + 6))
        fixed += 1
    return fixed


def _fix_align_self_call_reuse_sibling(blob: bytearray) -> int:
    """Align-stub ``call`` targeting its own ``push r13`` → reuse prior sibling call.

    When the previous align stub in the same function already calls the right
    callee (cmd ``push 0x10; call ff31`` twice), copy that target.
    """
    pro = bytes.fromhex("41554989e54883ec204883e4f0")  # push r13…and rsp
    epi_head = bytes.fromhex("4c89ec415d")  # mov rsp,r13; pop r13
    fixed = 0
    n = len(blob)
    sites = []
    p = 0
    while True:
        j = blob.find(pro, p)
        if j < 0:
            break
        call_at = j + len(pro)
        if call_at + 5 <= n and blob[call_at] == 0xE8:
            if blob[call_at + 5:call_at + 5 + len(epi_head)] == epi_head:
                rel = struct.unpack_from("<i", blob, call_at + 1)[0]
                tgt = call_at + 5 + rel
                sites.append((j, call_at, tgt))
        p = j + 1
    for idx, (j, call_at, tgt) in enumerate(sites):
        if tgt != j:
            continue  # not a self-call
        # Prefer previous non-self sibling within 0x100 bytes
        donor = None
        for k in range(idx - 1, -1, -1):
            pj, pc, pt = sites[k]
            if call_at - pc > 0x100:
                break
            if pt != pj and 0 <= pt < n:
                donor = pt
                break
        if donor is None:
            continue
        struct.pack_into("<i", blob, call_at + 1, donor - (call_at + 5))
        fixed += 1
    return fixed


def main() -> int:
    src = pathlib.Path("build_univ258/cmd_probe_wfs.exe")
    dst = pathlib.Path("build_univ258/cmd_probe_jcc.exe")
    pe_bytes = bytearray(src.read_bytes())
    va, rp, rs, blob = _text_blob(pe_bytes)

    n1 = _fix_zeroed_jcc_after_cmp(blob, va)
    n2 = _fix_je_to_success_epi(blob)
    n3 = _fix_align_self_call_reuse_sibling(blob)
    print(f"fixed zeroed-jcc={n1} je-success={n2} align-self={n3}")

    # Show the critical interactive sites
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    for rva in (0x458AF, 0x4599A, 0x459B4, 0x459BE):
        off = rva - va
        print(f"--- {rva:06X} ---")
        for insn in md.disasm(bytes(blob[off:off + 24]), 0x80000000 + rva):
            print(f"  {insn.address - 0x80000000:06X}: {insn.mnemonic} {insn.op_str}")
            if insn.address - 0x80000000 > rva + 12:
                break

    _write_text(pe_bytes, rp, bytes(blob)[:rs] if len(blob) >= rs else bytes(blob) + b"\x00" * (rs - len(blob)))
    # If blob grew we only write min(rs,len) — our patches are in-place
    pe_bytes[rp:rp + rs] = bytes(blob[:rs])
    dst.write_bytes(pe_bytes)
    print("wrote", dst)

    # Smoke /c
    r = subprocess.run(
        [sys.executable, "dbg_fault.py", str(dst), "/c", "echo", "w2ktest"],
        capture_output=True, text=True, timeout=60)
    print("=== /c echo ===")
    print((r.stdout or "")[-800:])
    print((r.stderr or "")[-400:])
    print("exit", r.returncode)

    # Interactive: feed echo + exit via stdin pipe
    print("=== interactive ===")
    p = subprocess.Popen(
        [sys.executable, "dbg_fault.py", str(dst)],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True)
    try:
        out, err = p.communicate(input="echo hi\r\nexit\r\n", timeout=25)
    except subprocess.TimeoutExpired:
        p.kill()
        out, err = p.communicate()
        print("TIMEOUT")
    print((out or "")[-1200:])
    print((err or "")[-600:])
    print("exit", p.returncode)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
