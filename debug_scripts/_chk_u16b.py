import struct
from pathlib import Path
from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_MODE_32

data=Path("build_univ16/cmd_pure.exe").read_bytes()
e=struct.unpack_from("<I", data, 0x3c)[0]
soh=struct.unpack_from("<H", data, e+20)[0]; sec=e+24+soh
num=struct.unpack_from("<H", data, e+6)[0]
base=struct.unpack_from("<Q", data, e+24+24)[0]
for i in range(num):
    o=sec+i*40
    if data[o:o+5]==b".text":
        vs,va,rs,rp=struct.unpack_from("<IIII", data, o+8)
        text=data[rp:rp+rs]; text_rva=va; break

md=Cs(CS_ARCH_X86, CS_MODE_64)
rva=0x14D40
off=rva-text_rva
print("bytes", text[off:off+64].hex())
print("=== PE64 around fault ===")
for insn in md.disasm(text[off:off+80], base+rva, count=25):
    mark=" <<<" if insn.address==base+0x14D6C else ""
    print(f"  {insn.address-base:#07x}  {insn.bytes.hex():24}  {insn.mnemonic} {insn.op_str}{mark}")

# reverse map
rev={}
rmap={}
for line in Path("build_univ16/rva.txt").read_text().splitlines():
    a,b=[int(x,16) for x in line.split()[:2]]
    rmap[a]=b
    rev.setdefault(b,[]).append(a)
print("\nx86 for pe near 14d6c:")
for pe,xs in sorted(rev.items()):
    if 0x14d40 <= pe <= 0x14da0:
        print(f"  {pe:#x} <- {[hex(x) for x in xs[:6]]}")

# Also check what's at rax path - maybe mov eax, 0x400 from wrong translation of TEB/fs
# Look at preceding instructions more carefully with larger window
print("\n=== wider window 0x14ce0 ===")
rva=0x14ce0
off=rva-text_rva
for insn in md.disasm(text[off:off+160], base+rva, count=40):
    mark=" <<<" if insn.address==base+0x14D6C else ""
    print(f"  {insn.address-base:#07x}  {insn.bytes.hex():24}  {insn.mnemonic} {insn.op_str}{mark}")
