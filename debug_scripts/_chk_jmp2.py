from capstone import Cs, CS_ARCH_X86, CS_MODE_64
import struct, pathlib
pe = bytearray(pathlib.Path("build_univ230/cmd_pure.exe").read_bytes())
e = struct.unpack_from("<I", pe, 0x3C)[0]
ns = struct.unpack_from("<H", pe, e+6)[0]; so=struct.unpack_from("<H", pe, e+20)[0]; sec=e+24+so
ib = struct.unpack_from("<Q", pe, e+24+24)[0]
for i in range(ns):
    o=sec+i*40
    if pe[o:o+5]==b".text":
        vs,va,rs,rp=struct.unpack_from("<IIII",pe,o+8); break
code=bytearray(pe[rp:rp+rs]); md=Cs(CS_ARCH_X86,CS_MODE_64)
# show jmp at 24a17
for insn in md.disasm(code[0x24a0d-va:0x24a0d-va+0x15], ib+0x24a0d):
    print(f"{insn.address:#x}: {insn.mnemonic} {insn.op_str}")
# find 5b5f5ec9c3 after 24a1c
epi=bytes.fromhex("5b5f5ec9c3")
j=code.find(epi, 0x24a1c-va)
print("epi at", hex(ib+va+j) if j>=0 else None, "off", hex(j) if j>=0 else None)
# all jmps from 249e8..24e20
for i in range(0x249e8-va, 0x24e20-va):
    if code[i]==0xE9:
        rel=struct.unpack_from("<i",code,i+1)[0]
        print(f"jmp {ib+va+i:#x} -> {ib+va+i+5+rel:#x}")
    if code[i] in (0xEB,):
        print(f"jmp short {ib+va+i:#x} -> {ib+va+i+2+struct.unpack_from('<b',code,i+1)[0]:#x}")
