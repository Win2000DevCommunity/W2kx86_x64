import struct, pathlib
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
pe = bytearray(pathlib.Path("build_univ228/cmd_fix.exe").read_bytes())
e = struct.unpack_from("<I", pe, 0x3C)[0]
ns = struct.unpack_from("<H", pe, e+6)[0]
so = struct.unpack_from("<H", pe, e+20)[0]
sec = e+24+so
ib = struct.unpack_from("<Q", pe, e+24+24)[0]
for i in range(ns):
    o = sec+i*40
    if pe[o:o+5]==b".text":
        vs,va,rs,rp=struct.unpack_from("<IIII", pe, o+8); break
blob=pe[rp:rp+rs]
md=Cs(CS_ARCH_X86, CS_MODE_64)
tip=b"\x48\xc7\xc2"+struct.pack("<I",0x2d)
j=blob.find(tip)
print("diamond after fix:")
for insn in md.disasm(bytes(blob[j-20:j+50]), ib+va+j-20):
    print(f"  {insn.address-ib:05x}: {insn.mnemonic} {insn.op_str}")

# check 1a05c area for heapsize corruption  
print("\nheapsize area:")
for insn in md.disasm(bytes(blob[0x1a050-va:0x1a050-va+0x40]), ib+0x1a050):
    print(f"  {insn.address-ib:05x}: {insn.mnemonic} {insn.op_str}")
