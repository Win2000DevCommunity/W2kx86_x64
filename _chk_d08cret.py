from capstone import Cs, CS_ARCH_X86, CS_MODE_64
import struct, pathlib
pe=bytearray(pathlib.Path("build_univ230/cmd_fix3.exe").read_bytes())
e=struct.unpack_from("<I",pe,0x3C)[0]
ns=struct.unpack_from("<H",pe,e+6)[0]; so=struct.unpack_from("<H",pe,e+20)[0]; sec=e+24+so
ib=struct.unpack_from("<Q",pe,e+24+24)[0]
for i in range(ns):
    o=sec+i*40
    if pe[o:o+5]==b".text":
        vs,va,rs,rp=struct.unpack_from("<IIII",pe,o+8); break
code=bytes(pe[rp:rp+rs]); md=Cs(CS_ARCH_X86,CS_MODE_64)
# find all ret between d08c and e000
for insn in md.disasm(code[0xd08c-va:0xe000-va], ib+0xd08c):
    if insn.mnemonic=="ret":
        print(f"{insn.address:#x}: ret")
        # show before
        for i2, ins2 in enumerate(md.disasm(code[insn.address-ib-va-0x20:insn.address-ib-va+1], insn.address-0x20)):
            print(f"  {ins2.address:#x}: {ins2.mnemonic} {ins2.op_str}")
        print("---")
