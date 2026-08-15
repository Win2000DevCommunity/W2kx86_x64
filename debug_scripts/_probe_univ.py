import struct, pathlib, subprocess, sys
from x86x64.translator._healing import HealingMixin

class T(HealingMixin):
    pass

pe = bytearray(pathlib.Path("build_univ257/cmd_pure.exe").read_bytes())
e = struct.unpack_from("<I", pe, 0x3C)[0]
ns = struct.unpack_from("<H", pe, e + 6)[0]; so = struct.unpack_from("<H", pe, e + 20)[0]; sec = e + 24 + so
for i in range(ns):
    o = sec + i * 40
    name = pe[o:o+8].split(b"\0")[0]
    vs, va, rs, rp = struct.unpack_from("<IIII", pe, o + 8)
    print(name, hex(va), "vs", hex(vs), "rs", hex(rs), "rp", hex(rp))
    if name == b".text":
        text_o, text_va, text_rs, text_rp = o, va, rs, rp

blob = bytearray(pe[text_rp:text_rp + text_rs])
t = T(); t._cmd_no_hacks = True; t._pure_cave_cursor = 0; t.new_base = 0x80000000
# populate iat map from pe
import pefile
ppe = pefile.PE(data=bytes(pe))
t._iat_name_to_new_rva = {}
for exp in ppe.DIRECTORY_ENTRY_IMPORT:
    for imp in exp.imports:
        if imp.name and imp.address:
            t._iat_name_to_new_rva[(exp.dll.decode(), imp.name.decode())] = imp.address - 0x80000000

print("ecx", t._pure_fix_missing_push_ecx_local_before_csr(blob))
print("gle1", t._pure_fix_stale_getlasterror_exitprocess1(blob))
print("exitw", t._pure_fix_exitprocess_wrapper_via_terminate(blob))
print("wexit", t._pure_fix_peb_c_infinite_waiter_exits(blob))
print("rjoin", t._pure_fix_reg_arg_join_skips_stdcall_add_rsp(blob))
print("blob len", len(blob), "rs", text_rs)

# If blob grew, need to extend file - for probe try to fit in existing rs
if len(blob) > text_rs:
    print("GREW by", len(blob)-text_rs, "- truncating risk")
    # bump section raw size if file has slack; else write expanded
    # Simplest: append to end of file and update headers - heavy.
    # Check if VirtualSize allows and raw has padding in file
    pe[text_rp:text_rp+text_rs] = blob[:text_rs]
    print("WARNING truncated caves")
else:
    pe[text_rp:text_rp+text_rs] = blob

outp = pathlib.Path("build_univ257/cmd_probe_univ.exe")
outp.write_bytes(pe)
print("wrote", outp)

p = subprocess.Popen([sys.executable, "dbg_fault.py", str(outp), "/c", "echo", "w2ktest"],
                     stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
try:
    out, _ = p.communicate(timeout=15)
    status = f"DONE exit={p.returncode}"
except subprocess.TimeoutExpired:
    p.kill(); out, _ = p.communicate(); status = "TIMEOUT"
print(status)
text = out.decode("utf-8", "replace").encode("ascii", "replace").decode()
print(text[:2000])
