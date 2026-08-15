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
    name = bytes(x86[o:o+8]).split(b"\0")[0]
    vs,va,rs,rp = struct.unpack_from("<IIII", x86, o+8)
    if name.startswith(b".text"):
        text = bytes(x86[rp:rp+rs]); tr = va; break
md = Cs(CS_ARCH_X86, CS_MODE_32)
target = struct.pack("<I", ib+0x1fbc4)
idx = 0; hits = []
while True:
    j = text.find(b"\xc7\x05", idx)
    if j < 0: break
    if text[j+2:j+6] == target:
        hits.append(tr+j)
    idx = j+1
print("mov [fbc4] sites", [hex(h) for h in hits])
for h in hits[:6]:
    off = h-tr
    print("====", hex(h))
    for insn in md.disasm(text[off-0x10:off+0x60], ib+h-0x10):
        print("  %x: %s %s" % (insn.address, insn.mnemonic, insn.op_str))
        if insn.address > ib+h+0x50: break

# also find push 8 / call ff31 sequence near Executer
# FF31 at rva 0xff31
print("==== x86 FF31 entry")
off = 0xff31-tr
for insn in md.disasm(text[off:off+0x40], ib+0xff31):
    print("  %x: %s %s" % (insn.address, insn.mnemonic, insn.op_str))
