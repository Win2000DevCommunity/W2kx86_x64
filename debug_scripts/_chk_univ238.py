import struct, pathlib
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
md=Cs(CS_ARCH_X86, CS_MODE_64)
pe=pathlib.Path("build_univ238/cmd_pure.exe").read_bytes()
e=struct.unpack_from("<I",pe,0x3C)[0]
ns=struct.unpack_from("<H",pe,e+6)[0]; so=struct.unpack_from("<H",pe,e+20)[0]; sec=e+24+so
secs=[]
for i in range(ns):
    o=sec+i*40
    nm=pe[o:o+8].split(b"\0")[0].decode(errors="replace")
    vs,va,rs,rp=struct.unpack_from("<IIII",pe,o+8)
    secs.append((nm,va,vs,rp,rs))
    print(f"  {nm:8s} va={va:#x} vs={vs:#x}")
def r2o(rva):
    for nm,va,vs,rp,rs in secs:
        if va<=rva<va+max(vs,rs): return rp+(rva-va)
# check key sites from prior diagnosis
for rva in (0x18f7f,0x18fa8,0x27204,0x27236,0x27265,0x27278,0x18e98,0x19029):
    o=r2o(rva)
    if o is None: print(f"{rva:#x}: NOT IN IMAGE"); continue
    print(f"\n==== {rva:#x} ====")
    for insn in md.disasm(pe[o:o+0x40], 0x80000000+rva):
        print(f"  {insn.address:#x}: {insn.mnemonic} {insn.op_str}")
        if insn.address >= 0x80000000+rva+0x30: break
# look for table pointer constant
print("\n==== movabs of 0x80047ce4 / 0x800588e8 ====")
bad=struct.pack("<Q",0x80047ce4); good=struct.pack("<Q",0x800588e8)
text=secs[0]; _,tva,_,trp,trs=text
blob=pe[trp:trp+trs]
for label,pat in (("BAD 47ce4",bad),("GOOD 588e8",good)):
    i=0; hits=[]
    while True:
        j=blob.find(pat,i)
        if j<0: break
        hits.append(tva+j)
        i=j+1
    print(f"  {label}: {[hex(h) for h in hits[:8]]}")
