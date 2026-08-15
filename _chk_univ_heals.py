import struct, pathlib, subprocess, sys, os
os.environ["PURE"]="1"
sys.path.insert(0, ".")
import dbg_fault as df

# Load pe64 text and x86 text, run the new heals standalone
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

x86p = pathlib.Path(r"C:\Users\win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU\cmd.exe")
x86 = x86p.read_bytes()
e2 = struct.unpack_from("<I", x86, 0x3C)[0]
ns2 = struct.unpack_from("<H", x86, e2+6)[0]
so2 = struct.unpack_from("<H", x86, e2+20)[0]
sec2 = e2+24+so2
for i in range(ns2):
    o = sec2+i*40
    if x86[o:o+5] == b".text":
        vs2,va2,rs2,rp2 = struct.unpack_from("<IIII", x86, o+8)
        text_data = x86[rp2:rp2+rs2]; text_rva = va2; break

# Minimal fake translator with just the heal methods
from x86x64.translator._healing import HealingMixin

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
        pro = bytes.fromhex("41554989e54883ec204883e4f0")
        epi = bytes.fromhex("4c89ec415d")
        return pro, epi

    def _pure_branch_site_ok(self, out, j):
        return True

t = T()
# seed empty rva_map - rely on pe64 fallbacks
n1 = t._pure_snap_jcc_off_bare_ret_to_epilogue(blob)
print("bare_ret", n1)
n2 = t._pure_retarget_calls_to_zero_quad_helper(blob, {}, text_data, text_rva)
print("zero_quad", n2)
n3 = t._pure_fix_geparse_followup_call(blob, {}, text_data, text_rva)
print("geparse", n3)

# also force diamond chain like before + arg4 if needed
sig = bytes.fromhex("4c894d285356574889c748897d28")
if blob.find(sig) >= 0:
    n4 = t._pure_restore_stdcall_arg4_mem_callback_call(blob)
    print("arg4", n4)

# diamond: reject bad, then manual chain for known tips
chain = {0x2d: (0x1d35c, 0x1d4f4), 0x2e: (0x1d4f4, 0x1d534), 0x2f: (0x1d534, 0x1d574), 0x30: (0x1d574, 0x1d5b4)}
for ch,(a,b) in chain.items():
    tip = b"\x48\xc7\xc2" + struct.pack("<I", ch)
    k = 0
    while True:
        j = blob.find(tip, k)
        if j < 0: break
        if j>=10 and blob[j-10:j-8]==b"\x48\xb9" and blob[j+7:j+9]==b"\x49\xb8":
            entry = j-10
            struct.pack_into("<Q", blob, entry+19, ib+a)
            struct.pack_into("<Q", blob, entry+29, ib+b)
        k=j+1

# snap mid-insn mov rcx,0x50
# find call to 19da7-like mid mov
for i in range(len(blob)-5):
    if blob[i]!=0xE8: continue
    rel=struct.unpack_from("<i",blob,i+1)[0]
    tgt=i+5+rel
    if 0<=tgt<len(blob)-7 and blob[tgt-3:tgt+4]==bytes.fromhex("48c7c150000000")[3:]:
        # landed on imm of mov rcx,0x50
        struct.pack_into("<i", blob, i+1, (tgt-3)-(i+5))
        print("snapped mid mov rcx at", hex(va+i))
    elif 0<=tgt<len(blob)-7 and blob[tgt:tgt+7]==bytes.fromhex("48c7c150000000"):
        pass

print("45862", hex(0x45862+5+struct.unpack_from("<i",blob,0x45862-va+1)[0]))
print("1d5dd", hex(0x1d5dd+5+struct.unpack_from("<i",blob,0x1d5dd-va+1)[0]))

pe[rp:rp+rs]=blob
pathlib.Path("build_univ227/cmd_univ.exe").write_bytes(pe)
df.suppress_fault_ui()
exe=pathlib.Path("build_univ227/cmd_univ.exe").resolve()
try:
 r=subprocess.run([str(exe),"/c","echo","w2ktest"],capture_output=True,timeout=25,cwd=str(exe.parent),creationflags=getattr(subprocess,"CREATE_NO_WINDOW",0))
 print("exit",hex(r.returncode&0xffffffff))
 print("out",repr(r.stdout[:500]))
 print(r.stdout.decode("utf-8","replace")[:400])
except subprocess.TimeoutExpired as ex:
 print("HANG",repr((ex.stdout or b"")[:500]))
