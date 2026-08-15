from pathlib import Path
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
import struct
pe=Path("build_univ98/cmd_pure.exe").read_bytes()
e=struct.unpack_from("<I",pe,0x3C)[0]
base=struct.unpack_from("<Q",pe,e+24+24)[0]
nsec=struct.unpack_from("<H",pe,e+6)[0]
osz=struct.unpack_from("<H",pe,e+20)[0]
soff=e+24+osz
for i in range(nsec):
    off=soff+i*40
    if pe[off:off+5]==b".text":
        vs,va,rs,rp=struct.unpack_from("<IIII",pe,off+8); break
text=pe[rp:rp+rs]
md=Cs(CS_ARCH_X86,CS_MODE_64); md.detail=True
more_lo, more_hi = 0x14742, 0x147a5
hits=[]
for insn in md.disasm(text, base+va):
    if insn.mnemonic in ("call","jmp","je","jne","ja","jb","jg","jl","jle","jge","jae","jbe","jz","jnz","js","jns","jp","jnp","jo","jno") or insn.mnemonic.startswith("j"):
        if not insn.operands: continue
        op=insn.operands[0]
        if op.type == 2: # IMM
            tgt = op.imm - base
            if more_lo <= tgt < more_hi:
                hits.append((insn.address-base, insn.mnemonic, tgt))
print("jumps into More? path:", len(hits))
for h in hits[:30]:
    print(f"  {h[0]:#x}: {h[1]} -> {h[2]:#x}")

# What is call target 0x2a230?
rmap={}
for line in Path("build_univ98/rva.txt").read_text().splitlines():
    a,b=line.replace("->"," ").split()[:2]
    rmap[int(a,16)]=int(b,16)
rev={v:k for k,v in rmap.items()}
print("2a230 x86", hex(rev.get(0x2a230,-1)))
print("158ee->", hex(rmap.get(0x158ee,-1)))
