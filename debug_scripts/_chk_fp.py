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
        if va<=rva<va+max(vs,rs): return rp+(rva-va)
print("==== 36235 (caller) ====")
o=r2o(0x36235)
for insn in md.disasm(pe[o:o+0x80], 0x80000000+0x36235):
    print(f"  {insn.address:#x}: {insn.mnemonic} {insn.op_str}")
print("==== 39888 area real ====")
o=r2o(0x39880)
print(pe[o:o+0x40].hex())
for insn in md.disasm(pe[o:o+0x40], 0x80000000+0x39880):
    print(f"  {insn.address:#x}: {insn.mnemonic} {insn.op_str}")
# what should 0x594f6 be? Check x86 cmd source data
src=pathlib.Path(r"C:\Users\win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU\cmd.exe").read_bytes()
se=struct.unpack_from("<I",src,0x3C)[0]
sns=struct.unpack_from("<H",src,se+6)[0]; sso=struct.unpack_from("<H",src,se+20)[0]; ssec=se+24+sso
for i in range(sns):
    o=ssec+i*40
    nm=src[o:o+8].split(b"\0")[0]
    vs,va,rs,rp=struct.unpack_from("<IIII",src,o+8)
    if nm.startswith(b".data"):
        print(f"x86 .data va={va:#x} vs={vs:#x}")
        # pe64 0x594f6 - data_new=0x58000, offset = 0x14f6
        # old data base?
        off=0x14f6
        print("x86 data+0x14f6", src[rp+off:rp+off+16].hex())
        # also try mapping: pe64 rva 0x594f6 -> old
