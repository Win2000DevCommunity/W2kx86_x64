import struct, pathlib, sys
sys.path.insert(0, ".")
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

pe = bytearray(pathlib.Path("build_univ227/cmd_univ4.exe").read_bytes())
e = struct.unpack_from("<I", pe, 0x3C)[0]
ns = struct.unpack_from("<H", pe, e+6)[0]
so = struct.unpack_from("<H", pe, e+20)[0]
sec = e+24+so
ib = struct.unpack_from("<Q", pe, e+24+24)[0]
for i in range(ns):
    o = sec+i*40
    if pe[o:o+5] == b".text":
        vs,va,rs,rp = struct.unpack_from("<IIII", pe, o+8); break
blob = pe[rp:rp+rs]
md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True

def dis(start, n=80):
    off = start - va
    for insn in md.disasm(bytes(blob[off:off+n*3]), ib+start):
        print(f"  {insn.address-ib:05x}: {insn.mnemonic} {insn.op_str}")
        n -= 1
        if n<=0: break

print("=== fbe4 body from 1e2c0 ===")
dis(0x1e2c0, 60)
print("=== around fault 1e250 ===")
dis(0x1e240, 40)
print("=== caller 1d940 ===")
dis(0x1d940, 40)
