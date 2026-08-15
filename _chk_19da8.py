from capstone import Cs, CS_ARCH_X86, CS_MODE_64
import struct, pathlib
pe = bytearray(pathlib.Path("build_univ227/cmd_fbe4.exe").read_bytes())
e = struct.unpack_from("<I", pe, 0x3C)[0]
ns = struct.unpack_from("<H", pe, e+6)[0]
so = struct.unpack_from("<H", pe, e+20)[0]
sec = e+24+so
for i in range(ns):
    o = sec+i*40
    if pe[o:o+5] == b".text":
        vs,va,rs,rp = struct.unpack_from("<IIII", pe, o+8); break
code = bytes(pe[rp:rp+rs])
md = Cs(CS_ARCH_X86, CS_MODE_64)
print("raw", code[0x19da0-va:0x19de0-va].hex())
print("==== 19d90")
for insn in md.disasm(code[0x19d90-va:0x19e50-va], 0x80000000+0x19d90):
    print("  %x: %s %s" % (insn.address, insn.mnemonic, insn.op_str))
# find function - look for prologue before
print("==== scan back for entry")
for off in range(0x19da7-va, max(0,0x19da7-va-0x40), -1):
    if code[off:off+4]==bytes.fromhex("48894c24") or code[off:off+2]==bytes.fromhex("4055") or code[off]==0x55:
        print("cand", hex(va+off), code[off:off+16].hex())

# x86: call target from fb2b or f041 path - 1eb9a context
print("==== 1eb60-1ebe0")
for insn in md.disasm(code[0x1eb40-va:0x1ebe0-va], 0x80000000+0x1eb40):
    print("  %x: %s %s" % (insn.address, insn.mnemonic, insn.op_str))
