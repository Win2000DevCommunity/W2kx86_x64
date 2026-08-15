import struct
from pathlib import Path
from capstone import Cs, CS_ARCH_X86, CS_MODE_32

src = Path(r"C:\Users\win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU\cmd.exe").read_bytes()
e = struct.unpack_from("<I", src, 0x3c)[0]
soh = struct.unpack_from("<H", src, e+20)[0]; sec = e+24+soh
num = struct.unpack_from("<H", src, e+6)[0]
obase = struct.unpack_from("<I", src, e+24+28)[0]
for i in range(num):
    o=sec+i*40
    if src[o:o+5]==b".text":
        vs,va,rs,rp=struct.unpack_from("<IIII", src, o+8)
        xt=src[rp:rp+rs]; xtr=va; break

md=Cs(CS_ARCH_X86, CS_MODE_32)
print("=== x86 0xb6e0..0xb780 ===")
for insn in md.disasm(xt[0xb6e0-xtr:0xb780-xtr], obase+0xb6e0, count=40):
    print(f"  {insn.address-obase:#07x}  {insn.bytes.hex():20}  {insn.mnemonic} {insn.op_str}")

# Search PE64 for pattern 0f 00 00 00 00 00 (broken jcc placeholders)
data=Path("build_univ16/cmd_pure.exe").read_bytes()
e=struct.unpack_from("<I", data, 0x3c)[0]
soh=struct.unpack_from("<H", data, e+20)[0]; sec=e+24+soh
num=struct.unpack_from("<H", data, e+6)[0]
for i in range(num):
    o=sec+i*40
    if data[o:o+5]==b".text":
        vs,va,rs,rp=struct.unpack_from("<IIII", data, o+8)
        text=data[rp:rp+rs]; text_rva=va; break
pat=b"\x0f\x00\x00\x00\x00\x00"
count=0; i=0
while True:
    j=text.find(pat,i)
    if j<0: break
    count+=1
    if count<=15:
        print(f"broken jcc at pe {text_rva+j:#x} ctx {text[j-4:j+8].hex()}")
    i=j+1
print("total broken 0f0000000000:", count)
