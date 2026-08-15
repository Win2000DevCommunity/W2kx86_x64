import struct, pathlib
pe = bytearray(pathlib.Path("build_univ225/cmd_f4eb.exe").read_bytes())
e = struct.unpack_from("<I", pe, 0x3C)[0]
ns = struct.unpack_from("<H", pe, e+6)[0]
so = struct.unpack_from("<H", pe, e+20)[0]
sec = e+24+so
ib = struct.unpack_from("<Q", pe, e+24+24)[0]
for i in range(ns):
    o = sec+i*40
    name = bytes(pe[o:o+8]).split(b"\0")[0]
    vs,va,rs,rp = struct.unpack_from("<IIII", pe, o+8)
    if name in (b".rdata", b".data", b".text"):
        print(name, hex(va), hex(ib+va))
        if ib+va <= 0x80047c08 < ib+va+vs:
            off = rp + (0x80047c08 - (ib+va))
            raw = pe[off:off+64]
            print("  @47c08", raw[:40], raw.decode("utf-16le","replace")[:40])
        if ib+va <= 0x800477c0 < ib+va+vs:
            off = rp + (0x800477c0 - (ib+va))
            raw = pe[off:off+32]
            print("  @477c0", raw.decode("utf-16le","replace")[:20])

# disasm 260fc start
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
for i in range(ns):
    o = sec+i*40
    if pe[o:o+5]==b".text":
        vs,va,rs,rp=struct.unpack_from("<IIII",pe,o+8); break
code=bytes(pe[rp:rp+rs]); md=Cs(CS_ARCH_X86,CS_MODE_64)
print("==== 260fc")
for insn in md.disasm(code[0x260fc-va:0x26180-va], 0x80000000+0x260fc):
    print("  %x: %s %s" % (insn.address, insn.mnemonic, insn.op_str))
