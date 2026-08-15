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
print("=== 14974 function (first 0x120) ===")
off = 0x14974 - 0x1000
for insn in md.disasm(bytes(blob[off:off + 0x120]), 0x80014974):
    print(f"0x{insn.address:x}: {insn.mnemonic} {insn.op_str}")

# x86 original - find in source cmd if we have refs
print("\n=== calls from 14974 to getchar 448b4? ===")
# scan 14974..14e00 for e8 to 448b4
for i in range(0x14974 - 0x1000, min(len(blob) - 5, 0x14e00 - 0x1000)):
    if blob[i] == 0xe8:
        rel = struct.unpack_from("<i", blob, i + 1)[0]
        tgt = 0x1000 + i + 5 + rel
        if tgt in (0x448b4, 0x448cb, 0x448c1):
            print("call getchar at", hex(0x1000 + i))