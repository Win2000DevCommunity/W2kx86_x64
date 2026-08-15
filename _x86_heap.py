import struct, pathlib
from capstone import Cs, CS_ARCH_X86, CS_MODE_32
x86 = pathlib.Path(r"C:\Users\win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU\cmd.exe").read_bytes()
e = struct.unpack_from("<I", x86, 0x3C)[0]
ns = struct.unpack_from("<H", x86, e+6)[0]
so = struct.unpack_from("<H", x86, e+20)[0]
sec = e+24+so
for i in range(ns):
    o = sec+i*40
    if x86[o:o+5]==b".text":
        vs,va,rs,rp=struct.unpack_from("<IIII", x86, o+8); break
xb=x86[rp:rp+rs]
# find HeapReAlloc IAT call - need import rva. Search FF 15 to known pattern near lea [ecx+0xc]
# 8d 79 0c = lea edi, [ecx+0xc]
idx=0
md=Cs(CS_ARCH_X86, CS_MODE_32)
while True:
    j=xb.find(bytes.fromhex("8d790c"), idx)
    if j<0: break
    print("hit", hex(va+j))
    for insn in md.disasm(xb[j-0x20:j+0x40], va+j-0x20):
        print(f"  {insn.address:04x}: {insn.mnemonic} {insn.op_str}")
    print()
    idx=j+1
    if idx>5: break
