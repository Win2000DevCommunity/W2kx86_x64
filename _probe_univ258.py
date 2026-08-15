"""Offline apply univ258-class heals and smoke /c echo w2ktest."""
import struct
import pathlib
import subprocess
import sys

import pefile
from x86x64.translator._healing import HealingMixin


class T(HealingMixin):
    pass


def rebuild_text(pe_bytes: bytearray, blob: bytearray) -> bytes:
    e = struct.unpack_from("<I", pe_bytes, 0x3C)[0]
    ns = struct.unpack_from("<H", pe_bytes, e + 6)[0]
    so = struct.unpack_from("<H", pe_bytes, e + 20)[0]
    sec = e + 24 + so
    fa = struct.unpack_from("<I", pe_bytes, e + 24 + 36)[0]
    sections = []
    for i in range(ns):
        o = sec + i * 40
        name = pe_bytes[o:o + 8].split(b"\0")[0].decode("ascii", "replace")
        vs, va, rs, rp = struct.unpack_from("<IIII", pe_bytes, o + 8)
        sections.append(
            {"o": o, "name": name, "vs": vs, "va": va, "rs": rs, "rp": rp})
    text = next(s for s in sections if s["name"] == ".text")
    new_rs = (len(blob) + fa - 1) & ~(fa - 1)
    blob_padded = bytes(blob) + b"\x00" * (new_rs - len(blob))
    sec_data = {}
    for s in sections:
        if s["name"] == ".text":
            sec_data[s["name"]] = blob_padded
            s["rs"] = new_rs
            s["vs"] = max(s["vs"], len(blob))
        else:
            sec_data[s["name"]] = bytes(
                pe_bytes[s["rp"]:s["rp"] + s["rs"]])
    hdr_end = min(s["rp"] for s in sections)
    fp = hdr_end
    for s in sections:
        s["rp"] = fp
        fp += s["rs"]
    out = bytearray(pe_bytes[:hdr_end])
    for s in sections:
        struct.pack_into("<I", out, s["o"] + 8, s["vs"])
        struct.pack_into("<I", out, s["o"] + 16, s["rs"])
        struct.pack_into("<I", out, s["o"] + 20, s["rp"])
    for s in sections:
        if len(out) < s["rp"]:
            out.extend(b"\x00" * (s["rp"] - len(out)))
        out.extend(sec_data[s["name"]])
    return bytes(out)


def main() -> int:
    src = pathlib.Path("build_univ257/cmd_pure.exe")
    pe_bytes = bytearray(src.read_bytes())
    e = struct.unpack_from("<I", pe_bytes, 0x3C)[0]
    ns = struct.unpack_from("<H", pe_bytes, e + 6)[0]
    so = struct.unpack_from("<H", pe_bytes, e + 20)[0]
    sec = e + 24 + so
    for i in range(ns):
        o = sec + i * 40
        if pe_bytes[o:o + 5] == b".text":
            _vs, _va, rs, rp = struct.unpack_from("<IIII", pe_bytes, o + 8)
            break
    blob = bytearray(pe_bytes[rp:rp + rs])
    t = T()
    t._cmd_no_hacks = True
    t._pure_cave_cursor = 0
    t.new_base = 0x80000000
    ppe = pefile.PE(data=bytes(pe_bytes))
    t._iat_name_to_new_rva = {}
    for exp in ppe.DIRECTORY_ENTRY_IMPORT:
        for imp in exp.imports:
            if imp.name and imp.address:
                t._iat_name_to_new_rva[(
                    exp.dll.decode(errors="replace"),
                    imp.name.decode(errors="replace"),
                )] = imp.address - 0x80000000

    print("ecx", t._pure_fix_missing_push_ecx_local_before_csr(blob))
    print("gle1", t._pure_fix_stale_getlasterror_exitprocess1(blob))
    print("exitw", t._pure_fix_exitprocess_wrapper_via_terminate(blob))
    print("sdone", t._pure_fix_peb_c_sticky_done_on_zero_ret_epi(blob))
    print("lexit", t._pure_fix_peb_c_lexer_exits_when_sticky_done(blob))
    print("rjoin", t._pure_fix_reg_arg_join_skips_stdcall_add_rsp(blob))
    print("push", t._pure_fix_push_reg_as_win64_arg0(blob))

    outp = pathlib.Path("build_univ257/cmd_probe_univ258.exe")
    outp.write_bytes(rebuild_text(pe_bytes, blob))
    print("wrote", outp, "size", outp.stat().st_size)

    p = subprocess.Popen(
        [sys.executable, "dbg_fault.py", str(outp), "/c", "echo", "w2ktest"],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    try:
        data, _ = p.communicate(timeout=15)
        status = f"DONE exit={p.returncode}"
    except subprocess.TimeoutExpired:
        p.kill()
        data, _ = p.communicate()
        status = "TIMEOUT"
    print(status)
    text = data.decode("utf-8", "replace").encode("ascii", "replace").decode()
    print(text[:2000])
    ok = (
        status.startswith("DONE")
        and p.returncode == 0
        and "w2ktest" in text
    )
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
