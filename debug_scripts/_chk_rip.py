import struct
from pathlib import Path
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

data = Path("build_univ15/cmd_pure.exe").read_bytes()
e = struct.unpack_from("<I", data, 0x3c)[0]
num = struct.unpack_from("<H", data, e+6)[0]; soh = struct.unpack_from("<H", data, e+20)[0]; sec = e+24+soh
base = struct.unpack_from("<Q", data, e+24+24)[0]
secs=[]
for i in range(num):
    o=sec+i*40
    name=data[o:o+8].split(b"\x00")[0].decode()
    vs,va,rs,rp=struct.unpack_from("<IIII", data, o+8)
    secs.append((name,va,vs,rs,rp))
    print(name, hex(va), hex(rs), hex(rp))

text=next(s for s in secs if s[0]==".text")
_,_,_,_,rp=text
va=text[1]
# RIP 0x8001482F -> rva 0x1482F
rva=0x1482F
off=rp+(rva-va)
print("bytes at fault:", data[off:off+32].hex())
md=Cs(CS_ARCH_X86, CS_MODE_64)
print("disasm around fault -16..+48:")
for insn in md.disasm(data[off-16:off+48], base+rva-16):
    mark=" <<<" if insn.address==base+rva else ""
    print(f"  {insn.address-base:#07x}  {insn.bytes.hex():24}  {insn.mnemonic} {insn.op_str}{mark}")

print("\ncaller 0x13F50..:")
rva2=0x13F50
off2=rp+(rva2-va)
for insn in md.disasm(data[off2:off2+80], base+rva2, count=25):
    print(f"  {insn.address-base:#07x}  {insn.bytes.hex():24}  {insn.mnemonic} {insn.op_str}")

# map 0x1482F back via rva.txt if possible
print("\nrva map reverse for ~0x1482f:")
hits=[]
for line in Path("build_univ15/rva.txt").read_text().splitlines():
    parts=line.split()
    if len(parts)>=2:
        try:
            a=int(parts[0],16); b=int(parts[1],16)
        except: continue
        if abs(b-0x1482f)<8 or abs(a-0x1482f)<8:
            hits.append((a,b,line))
print("hits", len(hits))
for h in hits[:20]:
    print(h)
