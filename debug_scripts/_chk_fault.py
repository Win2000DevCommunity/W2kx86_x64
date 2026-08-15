import pathlib, struct
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
base = pathlib.Path("build_univ30")
raw = (base/"cmd_pure.exe").read_bytes()
e = struct.unpack_from("<I", raw, 0x3C)[0]
n = struct.unpack_from("<H", raw, e+6)[0]
opt = struct.unpack_from("<H", raw, e+20)[0]
s0 = e+24+opt
for i in range(n):
    o=s0+i*40; name=raw[o:o+8].split(b"\x00")[0]
    vsz,va,rsz,rp=struct.unpack_from("<IIII", raw, o+8)
    if name.startswith(b".text"): break
text=raw[rp:rp+rsz]; text_rva=va
rev={}
for ln in (base/"rva.txt").read_text().splitlines():
    a=ln.split(); rev[int(a[1],16)]=int(a[0],16)
md=Cs(CS_ARCH_X86, CS_MODE_64)
print("bytes", text[0x1E40-text_rva:0x1E60-text_rva].hex())
for insn in md.disasm(text[0x1E20-text_rva:0x1E90-text_rva], 0x1E20):
    print(f"  {hex(insn.address)}: {insn.mnemonic} {insn.op_str}")
    if insn.address > 0x1E80: break
for tgt in (0x1E4E, 0x14E39, 0x11DB9):
    best=None
    for y,x in rev.items():
        if y<=tgt and (best is None or y>best[0]): best=(y,x)
    print(f"tgt {hex(tgt)} nearest {hex(best[0])} x86 {hex(best[1])} d={tgt-best[0]}")
