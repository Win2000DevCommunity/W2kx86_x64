import struct, pathlib
from capstone import Cs, CS_ARCH_X86, CS_MODE_32
src=pathlib.Path(r"C:\Users\win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU\cmd.exe").read_bytes()
e=struct.unpack_from("<I",src,0x3C)[0]; ib=struct.unpack_from("<I",src,e+24+28)[0]
nsec=struct.unpack_from("<H",src,e+6)[0]; sz=struct.unpack_from("<H",src,e+20)[0]; so=e+24+sz
for i in range(nsec):
    o=so+i*40; name=src[o:o+8].split(b"\0",1)[0]
    vsz,va,rsz,raw=struct.unpack_from("<IIII",src,o+8)
    if name.startswith(b".text"):
        text_va,text=va,src[raw:raw+rsz]; break
md=Cs(CS_ARCH_X86,CS_MODE_32)
print("=== x86 b420 ===")
fo=0xb420-text_va
for insn in md.disasm(text[fo:fo+80], ib+0xb420):
    print(f"  {insn.address:#x}: {insn.mnemonic} {insn.op_str}")