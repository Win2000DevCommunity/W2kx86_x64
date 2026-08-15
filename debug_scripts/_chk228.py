import struct, pathlib
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
pe = bytearray(pathlib.Path("build_univ228/cmd_pure.exe").read_bytes())
e = struct.unpack_from("<I", pe, 0x3C)[0]
ns = struct.unpack_from("<H", pe, e+6)[0]
so = struct.unpack_from("<H", pe, e+20)[0]
sec = e+24+so
ib = struct.unpack_from("<Q", pe, e+24+24)[0]
for i in range(ns):
    o = sec+i*40
    if pe[o:o+5]==b".text":
        vs,va,rs,rp=struct.unpack_from("<IIII", pe, o+8); break
blob=bytearray(pe[rp:rp+rs])
md=Cs(CS_ARCH_X86, CS_MODE_64)
# find mov rdx, 0x2d diamonds
tip=b"\x48\xc7\xc2"+struct.pack("<I",0x2d)
k=0
while True:
    j=blob.find(tip,k)
    if j<0: break
    print("site", hex(va+j))
    if j>=10:
        for insn in md.disasm(bytes(blob[j-20:j+40]), ib+va+j-20):
            print(f"  {insn.address-ib:05x}: {insn.mnemonic} {insn.op_str}")
    k=j+1
print("1d4f4", blob[0x1d4f4-va:0x1d4f4-va+8].hex())
print("1d4fe", blob[0x1d4fe-va:0x1d4fe-va+8].hex())
# check if heaprealloc pattern exists
sig=bytes.fromhex("4889c148c7c2000000004989c04989f9")
print("hr hits", blob.find(sig))
