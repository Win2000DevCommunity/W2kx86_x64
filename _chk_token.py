import struct, pathlib
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
md=Cs(CS_ARCH_X86, CS_MODE_64)
pe=pathlib.Path("build_univ238/cmd_probe2.exe").read_bytes()
e=struct.unpack_from("<I",pe,0x3C)[0]
ns=struct.unpack_from("<H",pe,e+6)[0]; so=struct.unpack_from("<H",pe,e+20)[0]; sec=e+24+so
for i in range(ns):
    o=sec+i*40
    if pe[o:o+5]==b".text":
        vs,va,rs,rp=struct.unpack_from("<IIII",pe,o+8); break
print("==== lookup token loop ====")
o=rp+(0x18ec0-va)
for insn in md.disasm(pe[o:o+0x80], 0x80000000+0x18ec0):
    print(f"  {insn.address:#x}: {insn.mnemonic} {insn.op_str}")
# show raw bytes of suspected stores
for rva in (0x18ed0,0x18ee0,0x18ef0,0x18f00,0x18f10,0x18f20,0x18f30,0x18f40,0x18f50,0x18f60,0x18f70):
    o=rp+(rva-va)
    print(hex(rva), pe[o:o+16].hex())
