import struct, pathlib, sys, os, subprocess, ast
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
orig_len = len(blob)

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
for name, fn in [
    ("bare", lambda: t._pure_snap_jcc_off_bare_ret_to_epilogue(blob)),
    ("arg0", lambda: t._pure_fix_arg0_loaded_from_r8_after_homes(blob)),
    ("mid", lambda: t._pure_snap_calls_into_mov_reg_imm(blob)),
    ("zq", lambda: t._pure_retarget_calls_to_zero_quad_helper(blob, {}, text_data, text_rva)),
    ("gpf", lambda: t._pure_fix_geparse_followup_call(blob, {}, text_data, text_rva)),
    ("dloc", lambda: t._pure_fix_frameless_dual_local_frame(blob)),
    ("pushimm", lambda: t._pure_fix_push_imm_jmp_to_mov_rcx_call(blob)),
    ("lcall", lambda: t._pure_fix_locale_call_reg_iat_reload(blob)),
    ("stos", lambda: t._pure_fix_rep_stos_dest_clobber(blob)),
]:
    print(name, fn())
print("blob delta", len(blob)-orig_len)
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
if len(blob) > rs:
    # try to extend section raw size if file has room - else keep within and hope caves used padding
    print("WARN blob > rs", len(blob), rs)
    pe[rp:rp+rs] = blob[:rs]
else:
    pe[rp:rp+len(blob)] = blob
pathlib.Path("build_univ227/cmd_univ12.exe").write_bytes(pe)
df.suppress_fault_ui()
exe=pathlib.Path("build_univ227/cmd_univ12.exe").resolve()
r=subprocess.run([str(exe),"/c","echo","w2ktest"],capture_output=True,timeout=30,cwd=str(exe.parent),creationflags=getattr(subprocess,"CREATE_NO_WINDOW",0))
print("exit",hex(r.returncode&0xffffffff))
out=r.stdout.decode("utf-8","replace")
print(repr(r.stdout[:900]))
print("has w2ktest", "w2ktest" in out)
if (r.returncode&0xffffffff)!=0:
    sys.argv=["dbg_fault.py",str(exe),"/c","echo","w2ktest"]
    df.main()
