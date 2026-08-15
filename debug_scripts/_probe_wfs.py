"""Apply WFS IAT heal + prior univ258 fixes; smoke /c and interactive."""
import struct
import pathlib
import subprocess
import sys
import time

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
    new_rs = (len(blob) + fa - 1) & ~(fa - 1)
    blob_padded = bytes(blob) + b"\x00" * (new_rs - len(blob))
    sec_data = {}
    for s in sections:
        if s["name"] == ".text":
            sec_data[s["name"]] = blob_padded
            s["rs"] = new_rs
            s["vs"] = max(s["vs"], len(blob))
        else:
            sec_data[s["name"]] = bytes(pe_bytes[s["rp"]:s["rp"] + s["rs"]])
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
    # Start from univ258 build output (has sticky heals) and add WFS + residual rjoin
    src = pathlib.Path("build_univ258/cmd_pure.exe")
    # Prefer pristine from build if probe overwrote — use build log pure; probe_rjoin may be current
    # Re-read: cmd_pure was overwritten with probe_rjoin. Apply WFS on top.
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

    print("wfs", t._pure_fix_infinite_wait_iat_to_waitforsingleobject(blob))
    print("rjoin", t._pure_fix_reg_arg_join_skips_stdcall_add_rsp(blob))

    if len(blob) > rs:
        out_bytes = rebuild_text(pe_bytes, blob)
    else:
        pe_bytes[rp:rp + rs] = blob
        out_bytes = bytes(pe_bytes)

    outp = pathlib.Path("build_univ258/cmd_probe_wfs.exe")
    outp.write_bytes(out_bytes)
    print("wrote", outp)

    # /c smoke
    p = subprocess.Popen(
        [sys.executable, "dbg_fault.py", str(outp), "/c", "echo", "w2ktest"],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    try:
        data, _ = p.communicate(timeout=12)
        print(f"/c DONE exit={p.returncode}")
    except subprocess.TimeoutExpired:
        p.kill()
        data, _ = p.communicate()
        print("/c TIMEOUT")
    print(data.decode("utf-8", "replace").encode("ascii", "replace").decode()[:800])

    # interactive: no stdin for 2s — should NOT stack-overflow
    p2 = subprocess.Popen(
        [sys.executable, "dbg_fault.py", str(outp)],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    time.sleep(2.5)
    try:
        p2.stdin.write(b"echo hi\r\nexit\r\n")
        p2.stdin.flush()
    except Exception:
        pass
    try:
        data2, _ = p2.communicate(timeout=6)
        print(f"interactive DONE exit={p2.returncode}")
    except subprocess.TimeoutExpired:
        p2.kill()
        data2, _ = p2.communicate()
        print("interactive TIMEOUT (may be waiting on console — OK if no SO)")
    text2 = data2.decode("utf-8", "replace").encode("ascii", "replace").decode()
    print(text2[:1200])
    bad = "C00000FD" in text2.upper() or "stack overflow" in text2.lower()
    print("stack_overflow" if bad else "no_stack_overflow")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
