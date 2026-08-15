import pefile, struct
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
pe = pefile.PE("build_univ257/cmd_probe_all.exe")
text = bytearray(pe.get_data(0x1000, 0x57000))
# find E8 rel32 targeting 0x14818
target = 0x14818
for off in range(len(text) - 5):
    if text[off] != 0xE8:
        continue
    rel = struct.unpack_from("<i", text, off + 1)[0]
    dest = off + 0x1000 + 5 + rel
    if dest == target:
        print(f"call from {off+0x1000:#x}")
