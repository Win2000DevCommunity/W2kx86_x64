import pathlib, struct
from capstone import Cs, CS_ARCH_X86, CS_MODE_32

src = pathlib.Path(
    r"C:\Users\win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU\cmd.exe"
).read_bytes()
e = struct.unpack_from("<I", src, 0x3C)[0]
n = struct.unpack_from("<H", src, e + 6)[0]
opt = struct.unpack_from("<H", src, e + 20)[0]
ib = struct.unpack_from("<I", src, e + 24 + 28)[0]
s0 = e + 24 + opt
for i in range(n):
    o = s0 + i * 40
    name = src[o : o + 8].split(b"\x00")[0]
    vsz, va, rsz, rp = struct.unpack_from("<IIII", src, o + 8)
    if name.startswith(b".text"):
        blob = src[rp : rp + rsz]
        tva = va
        break

# Find all E8 calls to e846
target = 0xE846
callers = []
for i in range(len(blob) - 5):
    if blob[i] != 0xE8:
        continue
    rel = struct.unpack_from("<i", blob, i + 1)[0]
    dest = (tva + i + 5 + rel) & 0xFFFFFFFF
    if dest == target:
        callers.append(tva + i)
print("callers of e846:", [hex(c) for c in callers])

# Check if e846 looks like function start (not mid-insn)
md = Cs(CS_ARCH_X86, CS_MODE_32)
print("prologue:")
for insn in md.disasm(blob[target - tva : target - tva + 40], target):
    print(f"  {hex(insn.address)}: {insn.mnemonic} {insn.op_str}")
    if insn.address > target + 30:
        break

# Is e846 reachable only via call (should be entry)?
print("bytes before", blob[target - tva - 4 : target - tva].hex())
