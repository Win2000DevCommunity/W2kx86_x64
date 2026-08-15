import struct, pathlib
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

raw = pathlib.Path("build_univ208/cmd_pure.exe").read_bytes()
pe = struct.unpack_from("<I", raw, 0x3C)[0]
n = struct.unpack_from("<H", raw, pe + 6)[0]
opt = struct.unpack_from("<H", raw, pe + 20)[0]
sec = pe + 24 + opt
for i in range(n):
    off = sec + i * 40
    name = raw[off:off + 8].split(b"\0")[0]
    vsz, va, rsz, rptr = struct.unpack_from("<IIII", raw, off + 8)
    if name == b".text":
        blob = raw[rptr:rptr + rsz]
        break

md = Cs(CS_ARCH_X86, CS_MODE_64)

# Function containing store_fae0 at 1ea93 - find start
print("=== add9-like around 1ea50-1eb00 ===")
off = 0x1ea50 - 0x1000
for insn in md.disasm(bytes(blob[off:off + 0xc0]), 0x8001ea50):
    print(f"0x{insn.address:x}: {insn.mnemonic} {insn.op_str}")

# Who calls 1ea3c (called before 1d7f4)?
print("\n=== callers of 1ea3c ===")
for i in range(len(blob) - 5):
    if blob[i] == 0xe8:
        rel = struct.unpack_from("<i", blob, i + 1)[0]
        tgt = 0x1000 + i + 5 + rel
        if tgt == 0x1ea3c:
            print(hex(0x1000 + i))

# Entry of getchar and what calls it
print("\n=== callers of getchar 448b4 ===")
hits = []
for i in range(len(blob) - 5):
    if blob[i] == 0xe8:
        rel = struct.unpack_from("<i", blob, i + 1)[0]
        tgt = 0x1000 + i + 5 + rel
        if tgt == 0x448b4:
            hits.append(0x1000 + i)
print([hex(h) for h in hits[:30]], "count", len(hits))