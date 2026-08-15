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
print("==== x86 10005")
off = 0x10005 - tr
for insn in md.disasm(text[off:off+0x80], ib+0x10005):
    print("  %x: %s %s" % (insn.address, insn.mnemonic, insn.op_str))
    if insn.address > ib+0x10005+0x70: break
print("==== x86 f6fd echodisp start")
off = 0xf6fd - tr
for insn in md.disasm(text[off:off+0x30], ib+0xf6fd):
    print("  %x: %s %s" % (insn.address, insn.mnemonic, insn.op_str))
# who calls f6fd?
print("callers of f6fd")
for i in range(len(text)-5):
    if text[i]!=0xE8: continue
    rel=struct.unpack_from("<i",text,i+1)[0]
    tgt=(tr+i+5+rel)&0xFFFFFFFF
    if tgt == 0xf6fd:
        print(" from", hex(tr+i))
