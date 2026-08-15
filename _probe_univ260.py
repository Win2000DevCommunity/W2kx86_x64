"""Offline probe: longjmp -1 imm + movsxd shim on univ258 base."""
from __future__ import annotations

import pathlib
import struct
import subprocess
import sys

import pefile

ROOT = pathlib.Path(__file__).resolve().parent
SRC = ROOT / "build_univ258" / "cmd_pure.exe"
SHIM_SRC = ROOT / "build_univ258" / "w2kshim64.dll"
OUT_DIR = ROOT / "build_univ258" / "probe_lj1"
EXE = OUT_DIR / "cmd_probe_lj1.exe"
SHIM = OUT_DIR / "w2kshim64.dll"


def _text_blob(pe_bytes: bytearray) -> tuple[bytearray, int, int, int]:
    e = struct.unpack_from("<I", pe_bytes, 0x3C)[0]
    ns = struct.unpack_from("<H", pe_bytes, e + 6)[0]
    so = struct.unpack_from("<H", pe_bytes, e + 20)[0]
    sec = e + 24 + so
    for i in range(ns):
        o = sec + i * 40
        if pe_bytes[o:o + 5] == b".text":
            vs, va, rs, rp = struct.unpack_from("<IIII", pe_bytes, o + 8)
            return bytearray(pe_bytes[rp:rp + rs]), va, rs, rp
    raise RuntimeError("no .text")


def patch_exe() -> int:
    pe_bytes = bytearray(SRC.read_bytes())
    blob, va, rs, rp = _text_blob(pe_bytes)
    lj_iat = 0x80084E78
    bad = bytes.fromhex("48baffffffff00000000")
    good = bytes.fromhex("48c7c2ffffffff909090")
    tip = struct.pack("<Q", lj_iat)
    fixed = 0
    i = 0
    while i + 30 <= len(blob):
        at = blob.find(bad, i)
        if at < 0:
            break
        window = bytes(blob[at + 10:at + 40])
        if tip in window and b"\xff\xd0" in window:
            blob[at:at + len(good)] = good
            fixed += 1
            i = at + len(good)
        else:
            i = at + 1
    pe_bytes[rp:rp + rs] = blob
    EXE.write_bytes(pe_bytes)
    print(f"patched longjmp -1 sites: {fixed} -> {EXE}")
    return fixed


def patch_shim() -> None:
    data = bytearray(SHIM_SRC.read_bytes())
    pe = pefile.PE(data=bytes(data))
    rva = None
    for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
        if exp.name == b"longjmp":
            rva = exp.address
            break
    assert rva is not None
    for s in pe.sections:
        if s.VirtualAddress <= rva < s.VirtualAddress + s.SizeOfRawData:
            off = s.PointerToRawData + (rva - s.VirtualAddress)
            break
    else:
        raise RuntimeError("longjmp section")
    # mov eax,edx (89 D0); push r10; ret; int3
    # -> movsxd rax,edx (48 63 C2); push r10; ret
    old = bytes.fromhex("89d04152c3cc")
    new = bytes.fromhex("4863c24152c3")
    body = bytearray(data[off:off + 0x80])
    if old not in body:
        raise RuntimeError("shim pattern not found: " + body[-24:].hex())
    assert len(old) == len(new)
    at = body.index(old)
    body[at:at + len(old)] = new
    data[off:off + 0x80] = body
    SHIM.write_bytes(data)
    print(f"shim longjmp movsxd @ file+{off + at:#x} -> {SHIM}")


def smoke_c() -> int:
    r = subprocess.run(
        [sys.executable, str(ROOT / "dbg_fault.py"), str(EXE), "/c", "echo", "w2ktest"],
        cwd=str(OUT_DIR),
        capture_output=True,
        text=True,
        timeout=30,
    )
    out = (r.stdout or "") + (r.stderr or "")
    print("--- /c echo ---")
    print(out[-800:])
    print("exit", r.returncode)
    return r.returncode


def main() -> int:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    n = patch_exe()
    if n < 1:
        print("WARN: no -1 sites patched")
    patch_shim()
    return smoke_c()


if __name__ == "__main__":
    raise SystemExit(main())
