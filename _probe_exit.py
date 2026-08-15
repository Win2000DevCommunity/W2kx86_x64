import struct, pathlib, subprocess, sys
from x86x64.translator._healing import HealingMixin

class T(HealingMixin):
    pass

t = T()
t._cmd_no_hacks = True
t._pure_cave_cursor = 0
t.new_base = 0x80000000
t._iat_name_to_new_rva = {("KERNEL32.dll", "TerminateProcess"): 0x845E0}

pe = bytearray(pathlib.Path("build_univ257/cmd_pure.exe").read_bytes())
e = struct.unpack_from("<I", pe, 0x3C)[0]
ns = struct.unpack_from("<H", pe, e + 6)[0]
so = struct.unpack_from("<H", pe, e + 20)[0]
sec = e + 24 + so
for i in range(ns):
    o = sec + i * 40
    if pe[o:o + 5] == b".text":
        vs, va, rs, rp = struct.unpack_from("<IIII", pe, o + 8)
        break
blob = bytearray(pe[rp:rp + rs])
print("pushrcx", t._pure_fix_push_reg_as_win64_arg0(blob))
print("ecxloc", t._pure_fix_missing_push_ecx_local_before_csr(blob))
print("rjoin", t._pure_fix_reg_arg_join_skips_stdcall_add_rsp(blob))
print("exitw", t._pure_fix_exitprocess_wrapper_via_terminate(blob))
# show stub
print("14818", blob[0x14818 - va:0x14818 - va + 28].hex())
pe[rp:rp + rs] = blob
pathlib.Path("build_univ257/cmd_probe_exit.exe").write_bytes(pe)

p = subprocess.Popen(
    [sys.executable, "dbg_fault.py", r"build_univ257\cmd_probe_exit.exe", "/c", "echo", "w2ktest"],
    stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
)
try:
    out, _ = p.communicate(timeout=15)
    status = b"DONE rc=%d\n" % (p.returncode or 0)
except subprocess.TimeoutExpired:
    p.kill()
    out, _ = p.communicate()
    status = b"TIMEOUT\n"
open("_exit_out.txt", "wb").write(status + out)
print(status.decode())
print(out.decode("utf-8", "replace").encode("ascii", "replace").decode()[:1800])
