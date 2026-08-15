from capstone import Cs, CS_ARCH_X86, CS_MODE_64
import struct, pathlib
pe = bytearray(pathlib.Path("build_univ229/cmd_diam.exe").read_bytes())
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
md = Cs(CS_ARCH_X86, CS_MODE_64)
# find function containing 24a9b - scan back for push rbp
start=None
for off in range(0x24a9b-va, max(0,0x24a9b-va-0x80), -1):
    if code[off:off+4]==bytes.fromhex('554889e5'):
        start=off; break
print("func start", hex(ib+va+start) if start else None)
if start is not None:
    for i, insn in enumerate(md.disasm(code[start:start+0x120], ib+va+start)):
        print(f"  {insn.address:#x}: {insn.mnemonic} {insn.op_str}")
        if i>55: break

# scan for dword stores to rbp+0x1c / 0x14 / 0x24 across text near echo
print("\n==== dword stores to rbp+0x1c (high half of rdx home) near 24xxx/d0xx ====")
for rva in range(0x24000, 0x25000):
    pass
# use capstone on window
for insn in md.disasm(code[0x24800-va:0x24b00-va], ib+0x24800):
    if "rbp + 0x1c" in insn.op_str or "rbp + 0x14" in insn.op_str:
        if insn.mnemonic.startswith("mov"):
            print(f"  {insn.address:#x}: {insn.mnemonic} {insn.op_str}")
