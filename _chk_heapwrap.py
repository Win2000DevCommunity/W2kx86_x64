from capstone import Cs, CS_ARCH_X86, CS_MODE_64
import struct, pathlib
pe=bytearray(pathlib.Path("build_univ230/cmd_fix2.exe").read_bytes())
e=struct.unpack_from("<I",pe,0x3C)[0]
ns=struct.unpack_from("<H",pe,e+6)[0]; so=struct.unpack_from("<H",pe,e+20)[0]; sec=e+24+so
ib=struct.unpack_from("<Q",pe,e+24+24)[0]
for i in range(ns):
    o=sec+i*40
    if pe[o:o+5]==b".text":
        vs,va,rs,rp=struct.unpack_from("<IIII",pe,o+8); break
code=bytes(pe[rp:rp+rs]); md=Cs(CS_ARCH_X86,CS_MODE_64)
for label,rva in [("19dc4 alloc",0x19dc4),("19f94 realloc",0x19f94)]:
    print(f"\n==== {label} ====")
    for i, insn in enumerate(md.disasm(code[rva-va:rva-va+0x80], ib+rva)):
        print(f"  {insn.address:#x}: {insn.mnemonic} {insn.op_str}")
        if i>35: break
