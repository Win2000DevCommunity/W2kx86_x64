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
print("==== stores to [rbp+0x10] in d08c ====")
for insn in md.disasm(code[0xd08c-va:0xd08c-va+0x500], ib+0xd08c):
    if insn.address > ib+0xd590: break
    if "rbp + 0x10" in insn.op_str and insn.mnemonic.startswith("mov"):
        print(f"  {insn.address:#x}: {insn.mnemonic} {insn.op_str}")
print("\n==== region around alloc 0x410 path ====")
for insn in md.disasm(code[0xd480-va:0xd480-va+0x120], ib+0xd480):
    print(f"  {insn.address:#x}: {insn.mnemonic} {insn.op_str}")
