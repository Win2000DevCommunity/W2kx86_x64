from pathlib import Path
from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_MODE_32
import struct

root = Path(r"c:\Users\win2000\Desktop\Nouveau dossier\Nouveau dossier (9)\X86_X64")
pe_path = root / "build_univ91" / "cmd_pure.exe"
rmap_path = root / "build_univ91" / "rva.txt"
src = Path(r"C:\Users\win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU\cmd.exe")

rmap = {}
for ln in rmap_path.read_text().splitlines():
    a, b = ln.split()[:2]
    rmap[int(a, 16)] = int(b, 16)

# show map around ae32
keys = sorted(k for k in rmap if 0xad80 <= k <= 0xae60)
print("rva_map around ae32:")
for k in keys:
    print(f"  {k:#x} -> {rmap[k]:#x}")

# disasm x86 around ae2a-ae50
data32 = src.read_bytes()
e = struct.unpack_from("<I", data32, 0x3C)[0]
nsec = struct.unpack_from("<H", data32, e+6)[0]
osz = struct.unpack_from("<H", data32, e+20)[0]
soff = e+24+osz
for i in range(nsec):
    off = soff+i*40
    name = data32[off:off+8].split(b"\0",1)[0]
    vsz,va,rsz,raw = struct.unpack_from("<IIII", data32, off+8)
    if name==b".text":
        text_va32, text_raw32 = va, raw
        break
# image base for win2k cmd is typically 0x4ad00000
base32 = 0x4ad00000
# file off for VA 0x4ad0ae20
rva = 0xae20
fo = text_raw32 + (rva - text_va32)
md32 = Cs(CS_ARCH_X86, CS_MODE_32)
md32.detail = True
print("\nx86 around 0xae20:")
for insn in md32.disasm(data32[fo:fo+0x60], base32+rva):
    print(f"  {insn.address:#x}: {insn.mnemonic} {insn.op_str}")

# Find pe64 function entry for 0xadad / nearby
for xa in (0xadad, 0xad80, 0xada0, 0xae00, 0xae20, 0xae30, 0xae32, 0xae33, 0xae40):
    print(f"map {xa:#x}: {hex(rmap[xa]) if xa in rmap else 'MISSING'}")
