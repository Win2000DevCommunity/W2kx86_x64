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
# raw bytes around d9b0
print(code[0xd9b0-va:0xd9c6-va].hex())
print("==== d990 ====")
for insn in md.disasm(code[0xd980-va:0xd980-va+0x50], ib+0xd980):
    print(f"  {insn.address:#x}: {insn.mnemonic} {insn.op_str}")
# find all mov rsi,1; pop rsi; leave; ret
pat=bytes.fromhex("48c7c6010000005ec9c3")
idx=0
while True:
    j=code.find(pat, idx)
    if j<0: break
    print(f"pattern at {ib+va+j:#x}")
    idx=j+1
# also mov rsi,2
for imm in (1,2,5):
    pat=bytes([0x48,0xc7,0xc6,imm,0,0,0,0x5e,0xc9,0xc3])
    j=code.find(pat)
    print(f"mov rsi,{imm}; pop rsi; leave; ret", hex(ib+va+j) if j>=0 else None)
