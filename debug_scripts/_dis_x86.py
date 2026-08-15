import struct, sys
from capstone import Cs, CS_ARCH_X86, CS_MODE_32

path = r"C:\Users\win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU\cmd.exe"
d = open(path, "rb").read()
base = 0x4AD00000
rva = int(sys.argv[1], 16)
length = int(sys.argv[2], 16) if len(sys.argv) > 2 else 0x120
pe = struct.unpack_from("<I", d, 0x3C)[0]
opt = struct.unpack_from("<H", d, pe + 20)[0]
n = struct.unpack_from("<H", d, pe + 6)[0]
sec = pe + 24 + opt
for i in range(n):
    o = sec + i * 40
    if d[o : o + 8].split(b"\0")[0] == b".text":
        rp = struct.unpack_from("<I", d, o + 20)[0]
        tva = struct.unpack_from("<I", d, o + 12)[0]
        code = d[rp + (rva - tva) : rp + (rva - tva) + length]
        break
md = Cs(CS_ARCH_X86, CS_MODE_32)
for ins in md.disasm(code, base + rva):
    print(f"0x{ins.address - base:05X}: {ins.mnemonic} {ins.op_str}")
