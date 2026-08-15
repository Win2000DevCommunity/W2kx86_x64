# Find pe64 VA for x86 0xf4eb via scanning build for unique tip of F4EB
# F4EB starts: cmp dword [imm], 0; push esi; mov esi, 0x4000
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
import struct, pathlib
pe = bytearray(pathlib.Path("build_univ225/cmd_pure.exe").read_bytes())
e = struct.unpack_from("<I", pe, 0x3C)[0]
ns = struct.unpack_from("<H", pe, e+6)[0]
so = struct.unpack_from("<H", pe, e+20)[0]
sec = e+24+so
ib = struct.unpack_from("<Q", pe, e+24+24)[0]
for i in range(ns):
    o = sec+i*40
    if pe[o:o+5] == b".text":
        vs,va,rs,rp = struct.unpack_from("<IIII", pe, o+8); break
code = bytearray(pe[rp:rp+rs])
md = Cs(CS_ARCH_X86, CS_MODE_64)
# look for mov esi/reg, 0x4000 after cmp mem
hits = []
for i in range(len(code)-12):
    # 48 c7 c6 00 40 00 00 = mov rsi, 0x4000
    if code[i:i+7] == bytes.fromhex("48c7c600400000"):
        hits.append(va+i)
    # be 00 40 00 00 in 32-bit form unlikely
print("mov rsi,4000 at", [hex(h) for h in hits[:20]])
for h in hits[:8]:
    off = h-va
    print("====", hex(h))
    for insn in md.disasm(bytes(code[max(0,off-20):off+40]), ib+h-min(20,off)):
        print("  %x: %s %s" % (insn.address, insn.mnemonic, insn.op_str))
