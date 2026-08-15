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
def r2o(rva):
    for nm,va,vs,rp,rs in secs:
        if va<=rva<va+max(vs,rs): return rp+(rva-va), nm
    return None,None
for rva in (0x39895,0x36284,0x1d4fe,0x45867,0x1c6b0,0x17c31,0x594f6):
    o,nm=r2o(rva)
    print(f"\n==== {rva:#x} in {nm} ====")
    if o is None: print("  missing"); continue
    if nm!=".text":
        print("  raw", pe[o:o+32].hex())
        continue
    for insn in md.disasm(pe[o:o+0x50], 0x80000000+rva):
        print(f"  {insn.address:#x}: {insn.mnemonic} {insn.op_str}")
        if insn.address>0x80000000+rva+0x40: break
