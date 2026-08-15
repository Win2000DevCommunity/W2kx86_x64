import struct, pathlib, subprocess, sys
from x86x64.translator._healing import HealingMixin
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

class T(HealingMixin):
    pass

t = T(); t._cmd_no_hacks = True; t._pure_cave_cursor = 0; t.new_base = 0x80000000

pe = bytearray(pathlib.Path("build_univ257/cmd_pure.exe").read_bytes())
e = struct.unpack_from("<I", pe, 0x3C)[0]
ns = struct.unpack_from("<H", pe, e + 6)[0]; so = struct.unpack_from("<H", pe, e + 20)[0]; sec = e + 24 + so
for i in range(ns):
    o = sec + i * 40
    if pe[o:o + 5] == b".text":
        vs, va, rs, rp = struct.unpack_from("<IIII", pe, o + 8); break
blob = bytearray(pe[rp:rp + rs])

# Only apply ecx + rjoin + push, NOT exitw
print("ecx", t._pure_fix_missing_push_ecx_local_before_csr(blob))
print("push", t._pure_fix_push_reg_as_win64_arg0(blob))
print("rjoin", t._pure_fix_reg_arg_join_skips_stdcall_add_rsp(blob))

# Manual: at waiter 0x45828, if fae0==0, check sticky and terminate
# Find: movabs r11, 5bae0; cmp dword [r11], 0; jne
md = Cs(CS_ARCH_X86, CS_MODE_64)
# locate pattern 49 bb e0 ba 05 80 00 00 00 00 41 83 3b 00
pat = bytes.fromhex("49bbe0ba05800000000041833b00")
at = blob.find(pat)
print("waiter at", hex(at + va) if at >= 0 else None)

# Build cave: cmp sticky, 0; je wait; xor ecx,ecx; TerminateProcess(-1,0)
# For now patch je to skip wait when we inject: 
# Replace cmp [fae0],0; jne X with: call cave that checks sticky

pe[rp:rp + rs] = blob
path = pathlib.Path("build_univ257/cmd_probe_hangfix.exe")
path.write_bytes(pe)

# Instead of exitw: patch WaitForSingleObject infinite to timeout 0 when hanging? 
# Simpler test: run with create and after 2s TerminateProcess ourselves isn't the goal.

# Try: only apply exitw but NOP the early locale ExitProcess call at 0x17aa8
blob2 = bytearray(pe[rp:rp + rs])
# re-read pure
pe = bytearray(pathlib.Path("build_univ257/cmd_pure.exe").read_bytes())
blob2 = bytearray(pe[rp:rp + rs])
t2 = T(); t2._cmd_no_hacks = True; t2._pure_cave_cursor = 0; t2.new_base = 0x80000000
t2._pure_fix_missing_push_ecx_local_before_csr(blob2)
t2._pure_fix_push_reg_as_win64_arg0(blob2)
t2._pure_fix_reg_arg_join_skips_stdcall_add_rsp(blob2)
print("exitw", t2._pure_fix_exitprocess_wrapper_via_terminate(blob2))
# NOP the call at 0x17aa8 (locale /c early exit)
call_at = 0x17aa8 - va
print("call bytes", blob2[call_at:call_at+5].hex())
if blob2[call_at] == 0xE8:
    blob2[call_at:call_at+5] = b"\x90" * 5
    print("nopped early exit call")
pe[rp:rp + rs] = blob2
pathlib.Path("build_univ257/cmd_probe_exit2.exe").write_bytes(pe)

p = subprocess.Popen([sys.executable, "dbg_fault.py", r"build_univ257\cmd_probe_exit2.exe", "/c", "echo", "w2ktest"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
try:
    out, _ = p.communicate(timeout=12)
    status = b"DONE %d\n" % (p.returncode or 0)
except subprocess.TimeoutExpired:
    p.kill(); out, _ = p.communicate(); status = b"TIMEOUT\n"
print(status.decode())
print(out.decode("utf-8", "replace").encode("ascii", "replace").decode()[:1500])
