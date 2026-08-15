import struct, pathlib
from capstone import Cs, CS_ARCH_X86, CS_MODE_32
md=Cs(CS_ARCH_X86, CS_MODE_32)
src=pathlib.Path(r"C:\Users\win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU\cmd.exe").read_bytes()
se=struct.unpack_from("<I",src,0x3C)[0]
ob=struct.unpack_from("<I",src,se+0x34)[0]
sns=struct.unpack_from("<H",src,se+6)[0]; sso=struct.unpack_from("<H",src,se+20)[0]; ssec=se+24+sso
for i in range(sns):
    o=ssec+i*40
    if src[o:o+5]==b".text":
        vs,va,rs,rp=struct.unpack_from("<IIII",src,o+8); break
for rva in (0xf4eb,0xf5a8,0xf590,0xfd5d,0x1400,0x13f8):
    o=rp+(rva-va)
    print(f"\n==== x86 {rva:#x} ====")
    for insn in md.disasm(src[o:o+0x40], ob+rva):
        print(f"  {insn.address:#x}: {insn.mnemonic} {insn.op_str}")
        if insn.address>ob+rva+0x30: break
