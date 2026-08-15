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
# find prologue before 27b2
for start in range(0x27b2, 0x2700, -1):
    if xt[start-xtr:start-xtr+3] in (b"\x55\x8b\xec", b"\x55\x8B\xEC"):
        print("ebp frame at", hex(start)); break
    if xt[start-xtr:start-xtr+4]==b"\x53\x55\x56\x57":
        print("push block at", hex(start)); break
print("=== x86 0x2780..0x27d0 ===")
for insn in md.disasm(xt[0x2780-xtr:0x27d0-xtr], obase+0x2780, count=30):
    print(f"  {insn.address-obase:#07x}  {insn.bytes.hex():18}  {insn.mnemonic} {insn.op_str}")
