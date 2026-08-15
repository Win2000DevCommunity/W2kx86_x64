import pefile, struct
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
pe = pefile.PE("build_univ257/cmd_pure.exe")
text = pe.get_data(0x1000, 0x57000)
needle = struct.pack("<Q", 0x8005BAE0)
idx = 0
hits = []
while True:
    p = text.find(needle, idx)
    if p < 0: break
    hits.append(p + 0x1000)
    idx = p + 1
print("imm64 refs", [hex(h) for h in hits])
# also 48 8B 05 rip-rel to 5BAE0
for off in range(len(text)-7):
    if text[off:off+2] in (b"\x48\x8b", b"\x4c\x8b", b"\x48\x83", b"\x83\x3d"):
        pass
# search any instruction referencing
md = Cs(CS_ARCH_X86, CS_MODE_64)
# WaitForSingleObject IAT
for e in pe.DIRECTORY_ENTRY_IMPORT:
    for i in e.imports:
        if i.name and b"WaitForSingleObject" in i.name:
            print("WFS IAT", hex(i.address - pe.OPTIONAL_HEADER.ImageBase))

# from earlier transcript - waiter around 1Dxxx
for base in (0x1D000, 0x1C000, 0x1E000, 0x14000):
    blob = pe.get_data(base, 0x1000)
    for i in md.disasm(blob, 0x80000000+base):
        if "5bae0" in i.op_str.lower() or "5BAE0" in i.op_str:
            print(f"{i.address-0x80000000:06X}: {i.mnemonic} {i.op_str}")
