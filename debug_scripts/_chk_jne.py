from pathlib import Path
from tools.audit_calls import read_text_section, load_map
from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64
import struct

rmap = load_map(Path("build_univ14/rva.txt"))
print("0xefd0", hex(rmap.get(0xefd0, 0)))
print("0xef72", hex(rmap.get(0xef72, 0)))
for o in range(0xefc0, 0xeff0):
    if o in rmap: print(f"  {o:#x} -> {rmap[o]:#x}")

src = Path(r"C:\Users\win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU\cmd.exe").read_bytes()
e = struct.unpack_from("<I", src, 0x3c)[0]
num = struct.unpack_from("<H", src, e+6)[0]; soh = struct.unpack_from("<H", src, e+20)[0]; sec = e+24+soh
for i in range(num):
    o = sec+i*40
    if src[o:o+5] == b".text":
        va, rs, rp = struct.unpack_from("<III", src, o+12)
        text = src[rp:rp+rs]; text_rva = va; break
base = struct.unpack_from("<I", src, e+24+28)[0]
md = Cs(CS_ARCH_X86, CS_MODE_32)
print("\nx86 0xefc8:")
for insn in md.disasm(text[0xefc8-text_rva:0xeff0-text_rva], base+0xefc8, count=15):
    print(f"  {insn.address-base:#07x}  {insn.mnemonic} {insn.op_str}")

trva, data, _ = read_text_section(Path("build_univ14/cmd_pure.exe").read_bytes())
md64 = Cs(CS_ARCH_X86, CS_MODE_64)
print("\nx64 0x1adb1 (jne target):")
for insn in md64.disasm(data[0x1adb1-trva:0x1ade0-trva], 0x1adb1, count=15):
    print(f"  {insn.address:#07x}  {insn.mnemonic} {insn.op_str}")
print("\nx64 0x36d01 (map efd0?):")
xr = rmap.get(0xefd0, 0x36d01)
for insn in md64.disasm(data[xr-trva:xr-trva+40], xr, count=12):
    print(f"  {insn.address:#07x}  {insn.mnemonic} {insn.op_str}")
