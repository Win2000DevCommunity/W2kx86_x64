import struct, pathlib
from x86x64.translator._healing import HealingMixin
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

class T(HealingMixin):
    pass

pe = bytearray(pathlib.Path("build_univ257/cmd_pure.exe").read_bytes())
e = struct.unpack_from("<I", pe, 0x3C)[0]
ns = struct.unpack_from("<H", pe, e + 6)[0]; so = struct.unpack_from("<H", pe, e + 20)[0]; sec = e + 24 + so
for i in range(ns):
    o = sec + i * 40
    if pe[o:o + 5] == b".text":
        vs, va, rs, rp = struct.unpack_from("<IIII", pe, o + 8); break
blob = bytearray(pe[rp:rp + rs])
homes = bytes.fromhex('48894c240848895424104c894424184c894c2420')
csr = bytes.fromhex('53555657')
tip = bytes.fromhex('4831ed6a03396c241c5b895c2410')
at = blob.find(homes + csr + tip)
print("ecx pattern at", hex(at+va) if at>=0 else None)
# softer search
at2 = blob.find(tip)
print("tip alone", hex(at2+va) if at2>=0 else None)
if at2>=0:
    print("before tip", blob[at2-24:at2].hex())

t = T(); t._cmd_no_hacks = True; t._pure_cave_cursor = 0; t.new_base = 0x80000000
# mock _pure_find_padding_cave
print("ecxloc", t._pure_fix_missing_push_ecx_local_before_csr(blob))
print("exitw", t._pure_fix_exitprocess_wrapper_via_terminate(blob))
print("rjoin", t._pure_fix_reg_arg_join_skips_stdcall_add_rsp(blob))
print("push", t._pure_fix_push_reg_as_win64_arg0(blob))
