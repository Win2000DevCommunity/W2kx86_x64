import struct, pathlib
from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_MODE_32
pe = bytearray(pathlib.Path("build_univ227/cmd_univ10.exe").read_bytes())
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
print("=== 28f6c wmemset-like ===")
for insn in md.disasm(bytes(blob[0x28f6c-va:0x28f6c-va+50]), ib+0x28f6c):
    print(f"  {insn.address-ib:05x}: {insn.mnemonic} {insn.op_str}")

# x86 caller near similar - find lea ebp-0x228 pattern or call memset
# pe64 d1a4 area maps from x86 - search for sub esp large then wmemset
x86 = pathlib.Path(r"C:\Users\win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU\cmd.exe").read_bytes()
e2 = struct.unpack_from("<I", x86, 0x3C)[0]
ns2 = struct.unpack_from("<H", x86, e2+6)[0]
so2 = struct.unpack_from("<H", x86, e2+20)[0]
sec2 = e2+24+so2
for i in range(ns2):
    o = sec2+i*40
    if x86[o:o+5]==b".text":
        vs2,va2,rs2,rp2=struct.unpack_from("<IIII", x86, o+8); break
xb=x86[rp2:rp2+rs2]
md32=Cs(CS_ARCH_X86, CS_MODE_32)
# 8d 85 d8 fd ff ff = lea eax, [ebp-0x228]
idx=0
hits=[]
while True:
    j=xb.find(bytes.fromhex("8d85d8fdffff"), idx)
    if j<0: break
    hits.append(va2+j)
    idx=j+1
print("x86 lea ebp-228", [hex(h) for h in hits[:10]])
if hits:
    h=hits[0]
    for insn in md32.disasm(xb[h-va2-0x20:h-va2+0x40], h-0x20):
        print(f"  {insn.address:04x}: {insn.mnemonic} {insn.op_str}")
