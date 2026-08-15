import struct, pathlib
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

raw = pathlib.Path("build_univ204/cmd_pure.exe").read_bytes()
pe = struct.unpack_from("<I", raw, 0x3C)[0]
n = struct.unpack_from("<H", raw, pe + 6)[0]
opt = struct.unpack_from("<H", raw, pe + 20)[0]
sec = pe + 24 + opt
blob = None
for i in range(n):
    off = sec + i * 40
    name = raw[off:off + 8].split(b"\0")[0]
    vsz, va, rsz, rptr = struct.unpack_from("<IIII", raw, off + 8)
    if name == b".text":
        blob = raw[rptr:rptr + rsz]
        print("text", hex(va), hex(rsz))
        break

md = Cs(CS_ARCH_X86, CS_MODE_64)
pat = bytes.fromhex("3d00400000")
idx = 0
hits = []
while True:
    j = blob.find(pat, idx)
    if j < 0:
        break
    hits.append(0x1000 + j)
    idx = j + 1
print("cmp eax,0x4000 at", [hex(h) for h in hits])
for rva in hits[:4]:
    print("===", hex(rva))
    off = rva - 0x1000
    start = max(0, off - 0x10)
    for insn in md.disasm(bytes(blob[start:off + 0xa0]), 0x80000000 + 0x1000 + start):
        print(f"  0x{insn.address:x}: {insn.mnemonic} {insn.op_str}")

tip = b"\x49\xbb" + struct.pack("<Q", 0x8005BBE2) + b"\x66\x41\x83\x3b\x00"
p = blob.find(tip)
print("helper", hex(p), "rva", hex(0x1000 + p))
for insn in md.disasm(bytes(blob[p + 0x120:p + 0x1d0]), 0x80000000 + 0x1000 + p + 0x120):
    print(f"  0x{insn.address:x}: {insn.mnemonic} {insn.op_str}")