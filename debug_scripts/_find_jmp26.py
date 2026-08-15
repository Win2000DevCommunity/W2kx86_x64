import pefile, struct
pe = pefile.PE("build_univ257/cmd_probe_exit2.exe")
text = pe.get_data(0x1000, 0x57000)
target = 0x26B9C
for off in range(len(text) - 5):
    if text[off] == 0xE9:
        rel = struct.unpack_from("<i", text, off + 1)[0]
        if off + 0x1000 + 5 + rel == target:
            print(f"jmp from {off+0x1000:#x}")
    if text[off] == 0x0F and off + 5 < len(text) and 0x80 <= text[off+1] <= 0x8F:
        rel = struct.unpack_from("<i", text, off + 2)[0]
        if off + 0x1000 + 6 + rel == target:
            print(f"jcc from {off+0x1000:#x}")
