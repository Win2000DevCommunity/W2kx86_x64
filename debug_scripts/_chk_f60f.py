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
# function containing f60f - walk back to prologue
print("==== around f60f")
for insn in md.disasm(text[0xf5e0-tr:0xf720-tr], ib+0xf5e0):
    print("  %x: %s %s" % (insn.address, insn.mnemonic, insn.op_str))

# find function start - search backwards for common prologue
print("\ncallers of ~f5xx entry - find push ebp; mov ebp,esp near f5c0")
# scan for calls to addresses in f5c0-f6fd
for start in range(0xf5c0, 0xf620):
    pass
for i in range(len(text)-5):
    if text[i]!=0xE8: continue
    rel=struct.unpack_from("<i",text,i+1)[0]
    tgt=(tr+i+5+rel)&0xFFFFFFFF
    if 0xf5c0 <= tgt <= 0xf610:
        print(" call from", hex(tr+i), "to", hex(tgt))
