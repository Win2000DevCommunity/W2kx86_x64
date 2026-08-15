import struct, pathlib
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
md=Cs(CS_ARCH_X86, CS_MODE_64)
pe=pathlib.Path("build_univ240/cmd_pure.exe").read_bytes()
e=struct.unpack_from("<I",pe,0x3C)[0]
ns=struct.unpack_from("<H",pe,e+6)[0]; so=struct.unpack_from("<H",pe,e+20)[0]; sec=e+24+so
for i in range(ns):
    o=sec+i*40
    if pe[o:o+5]==b".text":
        vs,va,rs,rp=struct.unpack_from("<IIII",pe,o+8); break
def show(rva,n=0x40):
    o=rp+(rva-va)
    print(f"\n==== {rva:#x} ====")
    for insn in md.disasm(pe[o:o+n], 0x80000000+rva):
        print(f"  {insn.address:#x}: {insn.mnemonic} {insn.op_str}")
show(0x27227,0x20)
show(0x2725c,0x40)
show(0x3624d,0x40)
# and trampoline
o=rp+(0x18fa8-va)
print("\n==== follow 18fa8 ====")
for insn in md.disasm(pe[o:o+8], 0x80000000+0x18fa8):
    print(f"  {insn.address:#x}: {insn.mnemonic} {insn.op_str}")
    if insn.mnemonic=="jmp":
        t=insn.operands[0].imm
        show(t-0x80000000,0x20)
# constants
print("BAD 47ce4", pe[rp:rp+rs].find(struct.pack("<Q",0x80047ce4)))
print("GOOD 588e8", pe[rp:rp+rs].find(struct.pack("<Q",0x800588e8)))
print("BAD 594f6", pe[rp:rp+rs].find(struct.pack("<Q",0x800594f6)))
