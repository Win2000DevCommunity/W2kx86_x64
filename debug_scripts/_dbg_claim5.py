import struct, importlib
from pathlib import Path
from x86x64.pe.image32 import PE32Image
import x86x64.translator._misc as misc
importlib.reload(misc)

pe = PE32Image(Path(r"C:\Users\win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU\cmd.exe").read_bytes())
data = Path("build_univ18/cmd_pure.exe").read_bytes()
e = struct.unpack_from("<I", data, 0x3c)[0]
soh = struct.unpack_from("<H", data, e+20)[0]; sec = e+24+soh
num = struct.unpack_from("<H", data, e+6)[0]
for i in range(num):
    o=sec+i*40
    if data[o:o+5]==b".text":
        vs,va,rs,rp=struct.unpack_from("<IIII", data, o+8)
        text=bytearray(data[rp:rp+rs]); break
rmap={}
for line in Path("build_univ18/rva.txt").read_text().splitlines():
    a,b=[int(x,16) for x in line.split()[:2]]
    rmap[a]=b

class M(misc.MiscMixin):
    def __init__(self):
        self._cmd_no_hacks = True
        self.old_base = pe.image_base
        self._fn_entry_rvas = set()
        self._x86_cf = None
    def _resolve_call_target_off(self, out, target_rva, rva_map):
        return rva_map.get(target_rva)
    def _refine_shim_target_off(self, out, target_rva, tgt):
        return tgt

m=M()
for tgt in (0xb9c3, 0xb9dd):
    print(hex(tgt), "->", m._resolve_jcc_target_off(text, tgt, rmap))

# Instrument the method
td=pe.get_section_data(pe.section_for_rva(0x1000))
src = misc.MiscMixin._pure_patch_jcc_placeholders
import types

def hooked(self, out, rva_map, text_data, text_rva):
    result = []
    # copy-paste minimal: after picking best for p_off==0x14d6c print it
    # Just call original with a side channel
    orig_setitem = None
    hits=[]
    real = bytearray(out)
    n = src(self, real, rva_map, text_data, text_rva)
    # find what was written by comparing
    if real[0x14d6c-0x1000:0x14d6c-0x1000+6] != out[0x14d6c-0x1000:0x14d6c-0x1000+6]:
        print("changed to", real[0x14d6c-0x1000:0x14d6c-0x1000+6].hex())
    print("n", n)
    return n

# Manually step through claim for 14d6c with resolve
from capstone import Cs, CS_ARCH_X86, CS_MODE_32
from x86x64.translator._env import X86_OP_IMM
P=0x14d6c
at_pe={}
for xrva,peoff in rmap.items():
    at_pe.setdefault(peoff,[]).append(xrva)
md32=Cs(CS_ARCH_X86, CS_MODE_32); md32.detail=True
JCC_CC={'je':0x84,'jz':0x84,'jne':0x85,'jnz':0x85,'jl':0x8c,'jnge':0x8c,'jg':0x8f,'jnle':0x8f,'jle':0x8e,'jng':0x8e,'jge':0x8d,'jnl':0x8d,'jb':0x82,'jnae':0x82,'jc':0x82,'ja':0x87,'jnbe':0x87,'jbe':0x86,'jna':0x86,'jae':0x83,'jnb':0x83,'jnc':0x83,'js':0x88,'jns':0x89,'jo':0x80,'jno':0x81,'jp':0x8a,'jpe':0x8a,'jnp':0x8b,'jpo':0x8b}
best=None
for peoff in range(max(0,P-96),P+1):
  for xrva in at_pe.get(peoff,()):
    off=xrva-0x1000
    if off<0 or off+6>len(td): continue
    b0=td[off]
    if not (b0==0x0F or 0x70<=b0<=0x7F): continue
    ins=list(md32.disasm(td[off:off+16], pe.image_base+xrva, count=1))
    if not ins: continue
    insn=ins[0]
    if not insn.mnemonic.startswith('j') or insn.mnemonic=='jmp': continue
    if not insn.operands or insn.operands[0].type != X86_OP_IMM: continue
    cc=JCC_CC.get(insn.mnemonic)
    if cc is None: continue
    tgt_x86=(insn.operands[0].imm-pe.image_base)&0xffffffff
    tgt=m._resolve_jcc_target_off(text, tgt_x86, rmap)
    print(f"xrva={xrva:#x} cc={cc:#x} tgt_x86={tgt_x86:#x} tgt={None if tgt is None else hex(tgt)}")
    if tgt is None: continue
    cand=(P-peoff, xrva, cc, tgt)
    if best is None or cand < best: best=cand
print("BEST", best)
