# Find how +0x38/+0x3c stores are encoded near ffa2/fb2b/eEcho
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
import struct, pathlib
pe = bytearray(pathlib.Path("build_univ229/cmd_diam.exe" if pathlib.Path("build_univ229/cmd_diam.exe").exists() else "build_univ229/cmd_pure.exe").read_bytes())
# prefer cmd_pure
for name in ["build_univ229/cmd_pure.exe","build_univ229/cmd_diam.exe","build_univ202v/cmd_pure.exe"]:
    p=pathlib.Path(name)
    if p.exists():
        pe=bytearray(p.read_bytes()); print("using", name); break
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
md = Cs(CS_ARCH_X86, CS_MODE_64); md.detail=True
# scan fb2b region 0x1e0d4 and ffa2 0x1eb78 for stores to +0x38/+0x3c
for label,rva,n in [("fb2b",0x1e0d4,0x200),("ffa2",0x1eb78,0x180),("eEcho",0x189c4,0x100),("c468",0xc468,0x80)]:
    print(f"\n==== {label} @{rva:#x} stores/loads +0x38/+0x3c ====")
    for insn in md.disasm(code[rva-va:rva-va+n], ib+rva):
        s=insn.op_str
        if "+ 0x38" in s or "+ 0x3c" in s or "- 0x38" in s or "- 0x3c" in s:
            print(f"  {insn.address:#x}: {insn.mnemonic} {s}")
