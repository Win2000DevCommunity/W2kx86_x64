from pathlib import Path
from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_MODE_32
import struct

root = Path(r"c:\Users\win2000\Desktop\Nouveau dossier\Nouveau dossier (9)\X86_X64")
pe_path = root / "build_univ91" / "cmd_pure.exe"
rmap_path = root / "build_univ91" / "rva.txt"
src = Path(r"C:\Users\win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU\cmd.exe")

rmap = {}
inv = {}
for ln in rmap_path.read_text().splitlines():
    a, b = ln.split()[:2]
    xa, na = int(a,16), int(b,16)
    rmap[xa] = na
    inv.setdefault(na, []).append(xa)

def pe_text(data):
    e = struct.unpack_from("<I", data, 0x3C)[0]
    nsec = struct.unpack_from("<H", data, e+6)[0]
    osz = struct.unpack_from("<H", data, e+20)[0]
    soff = e+24+osz
    for i in range(nsec):
        off = soff+i*40
        name = data[off:off+8].split(b"\0",1)[0]
        vsz,va,rsz,raw = struct.unpack_from("<IIII", data, off+8)
        if name==b".text":
            return va, raw, rsz

data64 = pe_path.read_bytes()
va64, raw64, _ = pe_text(data64)
fo = raw64 + (0x14A60 - va64)
blob = data64[fo:fo+0x80]
print("raw bytes @0x14A60:", blob[:0x40].hex())
# find INT3
for i,b in enumerate(blob):
    if b == 0xCC:
        print(f"INT3 at RVA {0x14A60+i:#x}")

md = Cs(CS_ARCH_X86, CS_MODE_64)
# disasm from a bit earlier looking for function structure
# find nearest map keys
cands = sorted((abs(k-0x14A72), k, inv[k]) for k in inv if abs(k-0x14A72)<0x80)
print("nearby rva_map:")
for d,k,xs in cands[:20]:
    print(f"  pe64 {k:#x} <- x86 {[hex(x) for x in xs]}")

# disasm pe64 from 0x14A40
fo2 = raw64 + (0x14A40 - va64)
print("\n=== pe64 @0x14A40 ===")
for insn in md.disasm(data64[fo2:fo2+0x80], 0x80000000+0x14A40):
    mark = " <<<" if 0x14A70 <= (insn.address-0x80000000) <= 0x14A80 else ""
    print(f"  {insn.address:#x}: {insn.mnemonic} {insn.op_str}{mark}")

# x86 around afb0 / afa0
data32 = src.read_bytes()
va32, raw32, _ = pe_text(data32)
# find x86 for pe64 region via inverse - closest before
best = None
for k in sorted(inv):
    if k <= 0x14A72:
        best = k
x86s = inv[best]
print(f"\nbest pe64 {best:#x} -> x86 {[hex(x) for x in x86s]}")
xa = min(x86s)
fo32 = raw32 + (xa - 0x20 - va32)
md32 = Cs(CS_ARCH_X86, CS_MODE_32)
print(f"=== x86 from {xa-0x20:#x} ===")
for insn in md32.disasm(data32[fo32:fo32+0x80], 0x4ad00000+xa-0x20):
    print(f"  {insn.address:#x}: {insn.mnemonic} {insn.op_str}")
    if insn.address > 0x4ad00000+xa+0x40:
        break
