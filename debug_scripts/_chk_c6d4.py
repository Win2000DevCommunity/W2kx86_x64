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
print("==== c6d4 ====")
for i, insn in enumerate(md.disasm(code[0xc6d4-va:0xc6d4-va+0x80], ib+0xc6d4)):
    print(f"  {insn.address:#x}: {insn.mnemonic} {insn.op_str}")
    if i>35: break
# find d08c return eax setup near end
print("\n==== d08c last 0x100 before far jump ====")
# find leave/ret in d08c range
for insn in md.disasm(code[0xdd00-va:0xdeaa-va], ib+0xdd00):
    if "eax" in insn.op_str or insn.mnemonic in ("ret","leave","pop"):
        print(f"  {insn.address:#x}: {insn.mnemonic} {insn.op_str}")
