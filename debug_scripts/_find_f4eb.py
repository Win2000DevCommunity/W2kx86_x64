import struct, pathlib
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
md=Cs(CS_ARCH_X86, CS_MODE_64)
pe=pathlib.Path("build_univ238/cmd_pure.exe").read_bytes()
e=struct.unpack_from("<I",pe,0x3C)[0]
ns=struct.unpack_from("<H",pe,e+6)[0]; so=struct.unpack_from("<H",pe,e+20)[0]; sec=e+24+so
for i in range(ns):
    o=sec+i*40
    if pe[o:o+5]==b".text":
        vs,va,rs,rp=struct.unpack_from("<IIII",pe,o+8); break
# find cmp dword [abs],0 pattern for f4eb: 833D....00
# look for movabs of 8005bbc8 used at start of 36235 - different
# Search for signature of f4eb: cmp [mem],0; push rsi; mov esi,0x4000
sig=bytes.fromhex("be00400000")  # mov esi, 0x4000
hits=[]
i=rp
while True:
    j=pe.find(sig,i,rp+rs)
    if j<0: break
    hits.append(va+j-rp); i=j+1
print("mov esi,4000 at", [hex(h) for h in hits[:20]])
for h in hits[:5]:
    o=rp+(h-va)-20
    print(f"\n--- {h:#x}-20 ---")
    for insn in md.disasm(pe[o:o+0x50], 0x80000000+h-20):
        print(f"  {insn.address:#x}: {insn.mnemonic} {insn.op_str}")
