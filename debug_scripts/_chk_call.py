from pathlib import Path
from capstone import Cs, CS_ARCH_X86, CS_MODE_32
import struct

# Find x86 RVAs that map near caller 0x13f6c and target should-be 0x1482b
rmap = {}
rev = {}
for line in Path("build_univ15/rva.txt").read_text().splitlines():
    parts=line.split()
    if len(parts)<2: continue
    a=int(parts[0],16); b=int(parts[1],16)
    rmap[a]=b
    rev.setdefault(b,[]).append(a)

print("x86 sources for PE64 caller region 0x13f50-0x13f80:")
for pe, xs in sorted(rev.items()):
    if 0x13f50 <= pe <= 0x13f80:
        print(f"  pe64 {pe:#x} <- x86 {[hex(x) for x in xs]}")

print("\nx86 sources for PE64 target region 0x14820-0x14850:")
for pe, xs in sorted(rev.items()):
    if 0x14820 <= pe <= 0x14850:
        print(f"  pe64 {pe:#x} <- x86 {[hex(x) for x in xs]}")

# disasm x86 around b4d9
src = Path(r"C:\Users\win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU\cmd.exe").read_bytes()
e = struct.unpack_from("<I", src, 0x3c)[0]
num = struct.unpack_from("<H", src, e+6)[0]; soh = struct.unpack_from("<H", src, e+20)[0]; sec = e+24+soh
base = struct.unpack_from("<I", src, e+24+28)[0]
for i in range(num):
    o=sec+i*40
    if src[o:o+5]==b".text":
        vs,va,rs,rp=struct.unpack_from("<IIII", src, o+8)
        text=src[rp:rp+rs]; text_rva=va; break

md=Cs(CS_ARCH_X86, CS_MODE_32)
print("\n=== x86 around 0xb4d0 (callee) ===")
off=0xb4d0-text_rva
for insn in md.disasm(text[off:off+64], base+0xb4d0, count=20):
    print(f"  {insn.address-base:#07x}  {insn.mnemonic} {insn.op_str}")

# Find caller x86 - search which x86 maps to 0x13f6c
print("\nclosest map to call site 0x13f6c:")
best=None
for pe, xs in rev.items():
    if abs(pe-0x13f6c)<0x20:
        print(f"  pe {pe:#x} <- {[hex(x) for x in xs]}")

# Also search x86 calls to b4d9
print("\n=== x86 calls targeting ~0xb4d9 ===")
md.detail=True
for insn in md.disasm(text, base+text_rva):
    if insn.mnemonic=="call" and insn.op_str.startswith("0x"):
        tgt=int(insn.op_str,16)-base
        if abs(tgt-0xb4d9)<8 or abs(tgt-0xb4e0)<8:
            print(f"  {insn.address-base:#07x} call {tgt:#x}  map-> pe {rmap.get(insn.address-base)} / tgt pe {rmap.get(tgt)}")
