"""Apply univ259-era heals one-by-one onto univ258 cmd_pure; find /c breaker."""
from __future__ import annotations

import pathlib
import shutil
import struct
import subprocess
import sys

import pefile

# Import healer mixin
sys.path.insert(0, ".")
from x86x64.translator._healing import HealingMixin
from x86x64.translator._misc import MiscMixin


class T(HealingMixin, MiscMixin):
    pass


def load_text(pe_bytes: bytearray):
    e = struct.unpack_from("<I", pe_bytes, 0x3C)[0]
    ns = struct.unpack_from("<H", pe_bytes, e + 6)[0]
    so = struct.unpack_from("<H", pe_bytes, e + 20)[0]
    sec = e + 24 + so
    for i in range(ns):
        o = sec + i * 40
        if pe_bytes[o:o + 5] == b".text":
            vs, va, rs, rp = struct.unpack_from("<IIII", pe_bytes, o + 8)
            return va, rp, rs, bytearray(pe_bytes[rp:rp + rs])
    raise RuntimeError("no .text")


def smoke(exe: pathlib.Path) -> str:
    r = subprocess.run(
        [sys.executable, "dbg_fault.py", str(exe), "/c", "echo", "w2ktest"],
        capture_output=True, text=True, timeout=40)
    out = r.stdout or ""
    if "w2ktest" in out and "[exit] code=0x00000000" in out:
        return "OK"
    if "execute @ 0x0000000000000000" in out:
        return "NULL"
    if "0xC00000FD" in out:
        return "SO"
    if "EXCEPTION" in out:
        import re
        m = re.search(r"addr=0x([0-9A-Fa-f]+)", out)
        return f"AV@{m.group(1) if m else '?'}"
    return f"rc={r.returncode}"


def main() -> int:
    src = pathlib.Path("build_univ258/cmd_pure.exe")
    outdir = pathlib.Path("build_univ258/heal_bisect")
    outdir.mkdir(exist_ok=True)

    # Load x86 text for heals that need it
    x86_path = pathlib.Path(
        r"C:\Users\win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU\cmd.exe")
    x86 = pefile.PE(str(x86_path))
    text_src = None
    text_rva = 0x1000
    for s in x86.sections:
        if s.Name.startswith(b".text"):
            text_src = s.get_data()
            text_rva = s.VirtualAddress
            break

    pe0 = bytearray(src.read_bytes())
    va, rp, rs, blob0 = load_text(pe0)

    # Minimal rva_map: empty — some heals no-op
    t = T()
    t._cmd_no_hacks = True
    t._pure_cave_cursor = 0
    t.new_base = 0x80000000
    t.old_base = 0x4AD00000
    t.text_rva = va
    t._pure_heal_text = text_src
    t._pure_heal_text_rva = text_rva
    t._iat_name_to_new_rva = {}
    ppe = pefile.PE(data=bytes(pe0))
    for exp in ppe.DIRECTORY_ENTRY_IMPORT:
        for imp in exp.imports:
            if imp.name and imp.address:
                t._iat_name_to_new_rva[(exp.dll.decode(errors="replace"),
                                        imp.name.decode())] = (
                    imp.address - t.new_base)

    heals = [
        ("zeroed_jcc", lambda b: t._pure_fix_zeroed_jcc_after_cmp_success_epi(b)),
        ("align_sibling", lambda b: t._pure_fix_align_stub_self_call_reuse_sibling(b)),
        ("wfs_retired", lambda b: t._pure_fix_infinite_wait_iat_to_waitforsingleobject(b)),
    ]

    # Baseline
    base_exe = outdir / "base.exe"
    shutil.copy2(src, base_exe)
    # need shim beside
    shim = pathlib.Path("build_univ258/w2kshim64.dll")
    if shim.exists():
        shutil.copy2(shim, outdir / "w2kshim64.dll")
    print("baseline", smoke(base_exe))

    # Cumulative apply
    pe_bytes = bytearray(src.read_bytes())
    _, rp, rs, blob = load_text(pe_bytes)
    for name, fn in heals:
        n = fn(blob)
        pe_bytes[rp:rp + rs] = bytes(blob[:rs])
        dst = outdir / f"after_{name}.exe"
        dst.write_bytes(pe_bytes)
        print(f"after {name} (n={n}):", smoke(dst))

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
