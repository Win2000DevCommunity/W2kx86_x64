import struct
from capstone import Cs, CS_ARCH_X86, CS_MODE_32

path = r"C:\Users\win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU\cmd.exe"
d = open(path, "rb").read()
pe = struct.unpack_from("<I", d, 0x3C)[0]
opt = struct.unpack_from("<H", d, pe + 20)[0]
n = struct.unpack_from("<H", d, pe + 6)[0]
sec = pe + 24 + opt
for i in range(n):
    o = sec + i * 40
    if d[o : o + 8].split(b"\0")[0] == b".text":
        rp = struct.unpack_from("<I", d, o + 20)[0]
        rsz = struct.unpack_from("<I", d, o + 16)[0]
        tva = struct.unpack_from("<I", d, o + 12)[0]
        td = d[rp : rp + rsz]
        break

for pat, name in [
    (b"\xff\xd7", "call edi"),
    (b"\xff\xd6", "call esi"),
    (b"\x53\x55\x89\xd5", "push ebx push ebp mov ebp,edx"),
    (b"\x53\x56\x89\xea", "push ebx push esi mov edx,ebp"),
    (struct.pack("<I", 0x4AD40590), "imm40590"),
    (struct.pack("<I", 0x4AD018F7), "imm18f7"),
    (struct.pack("<I", 0x4AD22B00), "imm22b00"),
]:
    idx = 0
    hits = []
    while True:
        j = td.find(pat, idx)
        if j < 0:
            break
        hits.append(tva + j)
        idx = j + 1
    print(name, len(hits), [hex(h) for h in hits[:15]])

md = Cs(CS_ARCH_X86, CS_MODE_32)
for ins in md.disasm(td, 0x4AD00000 + tva):
    rva = ins.address - 0x4AD00000
    if ins.mnemonic == "call" and "edi" in ins.op_str:
        print(f"capstone call edi @ 0x{rva:X}: {ins.mnemonic} {ins.op_str}")
