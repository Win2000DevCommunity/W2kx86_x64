import struct
from pathlib import Path
import importlib
from x86x64.pe.pe32 import PE32Image
from x86x64.translator import Win2000Translator
import x86x64.translator._healing as he
importlib.reload(he)

src = Path(r"C:\Users\win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU\cmd.exe")
pe32 = PE32Image(src.read_bytes())
raw = bytearray(Path(r"C:\Users\win2000\Desktop\univ89\cmd_pure.exe").read_bytes())
e = struct.unpack_from("<I", raw, 0x3C)[0]
ns = struct.unpack_from("<H", raw, e + 6)[0]
so = struct.unpack_from("<H", raw, e + 20)[0]
sec = e + 24 + so
for i in range(ns):
    o = sec + i * 40
    name = raw[o:o+8].split(b"\x00")[0].decode()
    vs, va, rs, rp = struct.unpack_from("<IIII", raw, o + 8)
    if name == ".text":
        tr, rp0, rsz = va, rp, rs
        break
text = bytearray(raw[rp0:rp0+rsz])
rmap = {}
for line in Path("build_univ89/rva.txt").read_text().splitlines():
    a = line.split()
    if len(a) == 2:
        rmap[int(a[0], 16)] = int(a[1], 16)

sec_t, xt = pe32.get_text_section()
xtr = sec_t.vaddr
fo = 0xafb4 - xtr
print("x86", xt[fo:fo+6].hex(), "next", hex(xt[fo+3]))

t = Win2000Translator(pe32, win10_test_shim=True)
t._cmd_no_hacks = True
t.new_base = 0x80000000
t._pure_heal_text_rva = tr

gap = 0x14a98 - tr
print("before gap", text[gap:gap+6].hex())
n = t._pure_fix_int3_omitted_ebp8_store(text, rmap, xt, xtr)
print("fixed", n)
print("after gap", text[gap:gap+6].hex())
print("14a90", text[0x14a90-tr:0x14aa8-tr].hex())
