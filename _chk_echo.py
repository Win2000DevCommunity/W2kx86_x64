import struct, pathlib
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
md=Cs(CS_ARCH_X86, CS_MODE_64)
pe=pathlib.Path("build_univ238/cmd_probe3.exe").read_bytes()
e=struct.unpack_from("<I",pe,0x3C)[0]
ns=struct.unpack_from("<H",pe,e+6)[0]; so=struct.unpack_from("<H",pe,e+20)[0]; sec=e+24+so
for i in range(ns):
    o=sec+i*40
    if pe[o:o+5]==b".text":
        vs,va,rs,rp=struct.unpack_from("<IIII",pe,o+8); break
for rva in (0x18ba0,0x19e00,0x19e29,0x1a07b,0x189c4):
    print(f"\n==== {rva:#x} ====")
    o=rp+(rva-va)
    for insn in md.disasm(pe[o:o+0x50], 0x80000000+rva):
        print(f"  {insn.address:#x}: {insn.mnemonic} {insn.op_str}")
        if insn.address>0x80000000+rva+0x40: break
