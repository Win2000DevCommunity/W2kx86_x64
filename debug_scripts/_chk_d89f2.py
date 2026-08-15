from capstone import Cs, CS_ARCH_X86, CS_MODE_64
import struct, pathlib
pe = bytearray(pathlib.Path("build_univ229/cmd_diam.exe").read_bytes())
e = struct.unpack_from("<I", pe, 0x3C)[0]
ns = struct.unpack_from("<H", pe, e+6)[0]
so = struct.unpack_from("<H", pe, e+20)[0]
sec = e+24+so
ib = struct.unpack_from("<Q", pe, e+24+24)[0]
for i in range(ns):
    o = sec+i*40
    if pe[o:o+5] == b".text":
        vs,va,rs,rp = struct.unpack_from("<IIII", pe, o+8); break
code = bytes(pe[rp:rp+rs])
print("len", len(code), "va", hex(va))
# find e8 that targets 249e8
target=0x249e8
hits=[]
for i in range(len(code)-5):
    if code[i]==0xE8:
        rel=struct.unpack_from("<i",code,i+1)[0]
        if i+5+rel==target:
            hits.append(ib+va+i)
print("direct calls to 249e8", [hex(h) for h in hits])
md = Cs(CS_ARCH_X86, CS_MODE_64)
for a in [0xd780, 0xd850, 0xd870]:
    print(f"\n==== {a:#x} ====")
    for insn in md.disasm(code[a-va:a-va+0x80], ib+a):
        print(f"  {insn.address:#x}: {insn.mnemonic} {insn.op_str}")
        if insn.address > ib+a+0x70: break
