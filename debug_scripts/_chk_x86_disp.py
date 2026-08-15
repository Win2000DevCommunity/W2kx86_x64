from capstone import Cs, CS_ARCH_X86, CS_MODE_32
import struct, pathlib
x86 = bytearray(pathlib.Path(r"C:\Users\win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU\cmd.exe").read_bytes())
e = struct.unpack_from("<I", x86, 0x3C)[0]
ns = struct.unpack_from("<H", x86, e+6)[0]
so = struct.unpack_from("<H", x86, e+20)[0]
sec = e+24+so
ib = struct.unpack_from("<I", x86, e+24+28)[0]
for i in range(ns):
    o = sec+i*40
    if x86[o:o+5] == b".text":
        vs,va,rs,rp = struct.unpack_from("<IIII", x86, o+8)
        text = bytes(x86[rp:rp+rs]); tr = va; break
md = Cs(CS_ARCH_X86, CS_MODE_32)
# Find: cmp [fae0], 0 / jne; near call after wrapper at eff7
# Main loop calling 0xefd0-ish - search for call to 0xefd0 or 0xeff0 range
# Disasm x86 function containing 0xeff7 - start of that func
print("==== x86 wrapper func start")
# walk back for prologue
off = 0xefd0 - tr
for insn in md.disasm(text[off:off+0x80], ib+0xefd0):
    print("  %x: %s %s" % (insn.address, insn.mnemonic, insn.op_str))

# Find callers of 0xefd0/eff0 area by scanning E8
target = 0xefd0
print("\ncallers near efd0-f040")
for i in range(len(text)-5):
    if text[i] != 0xE8: continue
    rel = struct.unpack_from("<i", text, i+1)[0]
    tgt = (tr+i+5+rel) & 0xFFFFFFFF
    if 0xefd0 <= tgt <= 0xf040:
        print("  from", hex(tr+i), "to", hex(tgt))

# Disasm around 0xdbxx main that might dispatch 4000
# Search cmp dword [fae0], 0x4000 = 813D e0fad14a 00400000
fae0 = struct.pack("<I", ib+0x1fae0)
pat = b"\x81\x3d" + fae0 + struct.pack("<I", 0x4000)
idx = 0
while True:
    j = text.find(pat, idx)
    if j < 0: break
    print("\ncmp fae0,4000 at", hex(tr+j))
    for insn in md.disasm(text[j:j+0x40], ib+tr+j):
        print("  %x: %s %s" % (insn.address, insn.mnemonic, insn.op_str))
    idx = j+1
