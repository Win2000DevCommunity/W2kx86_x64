import struct, pathlib, subprocess, sys, os, ast
os.environ["PURE"]="1"
sys.path.insert(0, ".")
ast.parse(open("x86x64/translator/_healing.py",encoding="utf-8").read())
print("syntax ok")
import dbg_fault as df
from x86x64.translator._healing import HealingMixin

pe = bytearray(pathlib.Path("build_univ227/cmd_pure.exe").read_bytes())
e = struct.unpack_from("<I", pe, 0x3C)[0]
ns = struct.unpack_from("<H", pe, e+6)[0]
so = struct.unpack_from("<H", pe, e+20)[0]
sec = e+24+so
ib = struct.unpack_from("<Q", pe, e+24+24)[0]
for i in range(ns):
    o = sec+i*40
    if pe[o:o+5] == b".text":
        vs,va,rs,rp = struct.unpack_from("<IIII", pe, o+8); break
blob = bytearray(pe[rp:rp+rs])

x86 = pathlib.Path(r"C:\Users\win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU\cmd.exe").read_bytes()
e2 = struct.unpack_from("<I", x86, 0x3C)[0]
ns2 = struct.unpack_from("<H", x86, e2+6)[0]
so2 = struct.unpack_from("<H", x86, e2+20)[0]
sec2 = e2+24+so2
for i in range(ns2):
    o = sec2+i*40
    if x86[o:o+5] == b".text":
        vs2,va2,rs2,rp2 = struct.unpack_from("<IIII", x86, o+8)
        text_data = x86[rp2:rp2+rs2]; text_rva = va2; break

class T(HealingMixin):
    def __init__(self):
        self._cmd_no_hacks = True
        self.pe = None
        self.rva_map = {}
        self.text_rva = text_rva
        self.old_base = 0
        self.new_base = ib
        self._final_rva = {}
        self._old_to_new_section = {text_rva: va}
    def _pure_align_stub_pro_epilogue(self):
        return bytes.fromhex("41554989e54883ec204883e4f0"), bytes.fromhex("4c89ec415d")
    def _pure_branch_site_ok(self, out, j):
        return True

t = T()
print("bare", t._pure_snap_jcc_off_bare_ret_to_epilogue(blob))
print("arg0", t._pure_fix_arg0_loaded_from_r8_after_homes(blob))
print("mid", t._pure_snap_calls_into_mov_reg_imm(blob))
print("zq", t._pure_retarget_calls_to_zero_quad_helper(blob, {}, text_data, text_rva))
print("gpf", t._pure_fix_geparse_followup_call(blob, {}, text_data, text_rva))
print("dloc", t._pure_fix_frameless_dual_local_frame(blob))
print("r13", t._pure_fix_frameless_r13_local_reload(blob))
chain = {0x2d:(0x1d35c,0x1d4f4),0x2e:(0x1d4f4,0x1d534),0x2f:(0x1d534,0x1d574),0x30:(0x1d574,0x1d5b4)}
for ch,(a,b) in chain.items():
    tip=b"\x48\xc7\xc2"+struct.pack("<I",ch); k=0
    while True:
        j=blob.find(tip,k)
        if j<0: break
        if j>=10 and blob[j-10:j-8]==b"\x48\xb9" and blob[j+7:j+9]==b"\x49\xb8":
            e0=j-10
            struct.pack_into("<Q",blob,e0+19,ib+a)
            struct.pack_into("<Q",blob,e0+29,ib+b)
        k=j+1
# show fbe4 entry
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
md=Cs(CS_ARCH_X86, CS_MODE_64)
print("=== entry 1e2b4 ===")
for insn in md.disasm(bytes(blob[0x1e2b4-va:0x1e2b4-va+50]), ib+0x1e2b4):
    print(f"  {insn.address-ib:05x}: {insn.mnemonic} {insn.op_str}")
    if insn.address-ib>0x1e2e0: break
print("call 1d5dd ->", hex(0x1d5dd+5+struct.unpack_from("<i",blob,0x1d5dd-va+1)[0]))
print("call 1e257 ->", hex(0x1e257+5+struct.unpack_from("<i",blob,0x1e257-va+1)[0]))
print("early 1e5dd", blob[0x1e5dd-va:0x1e5dd-va+8].hex())
pe[rp:rp+rs]=blob
pathlib.Path("build_univ227/cmd_univ6.exe").write_bytes(pe)
df.suppress_fault_ui()
exe=pathlib.Path("build_univ227/cmd_univ6.exe").resolve()
sys.argv=["dbg_fault.py", str(exe), "/c", "echo", "w2ktest"]
df.main()
