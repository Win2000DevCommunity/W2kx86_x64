import struct
from pathlib import Path
import importlib
from x86x64.pe.pe32 import PE32Image
from x86x64.translator import Win2000Translator
import x86x64.translator._healing as he
importlib.reload(he)

# Start from pristine build_univ89
src_pe = Path("build_univ89/cmd_pure.exe")
dst = Path(r"C:\Users\win2000\Desktop\univ89\cmd_pure.exe")
raw = bytearray(src_pe.read_bytes())
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

pe32 = PE32Image(Path(r"C:\Users\win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU\cmd.exe").read_bytes())
sec_t, xt = pe32.get_text_section()
t = Win2000Translator(pe32, win10_test_shim=True)
t._cmd_no_hacks = True
t.new_base = 0x80000000
t._pure_heal_text_rva = tr

# 1) fix adad 22844 store
off = 0x14668 - tr
print("adad before", hex(struct.unpack_from("<Q", text, off+2)[0]))
struct.pack_into("<Q", text, off+2, 0x8006f844)
print("adad after", hex(struct.unpack_from("<Q", text, off+2)[0]))

# 2) omit-store
n = t._pure_fix_int3_omitted_ebp8_store(text, rmap, xt, sec_t.vaddr)
print("omit fixed", n, "gap", text[0x14a98-tr:0x14a98-tr+6].hex())

raw[rp0:rp0+len(text)] = text[:rsz] if len(text) <= rsz else text[:rsz]
# if text grew, need to extend - omit-store appends stubs!
if len(text) > rsz:
    print("TEXT GREW", rsz, "->", len(text), "need expand PE")
    # For smoke: write expanded .text if vsize allows
    if len(text) <= vs:
        # expand raw section in file - complex. Simpler: keep stubs by growing file section
        print("vsize ok", vs)
    else:
        print("vsize too small", vs)

# Write carefully: if grew, append to end of text raw and hope vsize covers
if len(text) > rsz:
    # Place grown bytes into virtual padding if raw_sz has room... usually raw==pad
    # Actually univ builds often have raw_sz == content; stubs append in memory during
    # translate then PE writer includes them. For offline, splice growth into section.
    growth = text[rsz:]
    print("growth", len(growth))
    # Expand file: insert growth after text raw
    new_raw = bytearray(raw)
    # Simple approach used before: write full text into section if raw_sz enough
    if len(text) <= rs:
        new_raw[rp0:rp0+len(text)] = text
    else:
        # extend raw size - update PE headers (minimal)
        new_raw[rp0:rp0+rs] = text[:rs]
        # put overflow at end of image file and fix - too hard
        # Instead patch in-place with short trampoline without extending:
        # mov [rbp+0x10], esi; jmp original ? fits in 3+5 if we overwrite int3+jmp
        # 89 75 10 = mov [rbp+0x10], esi (ebp+8 ? rbp+0x10)
        # then need jmp - original jmp is 5 bytes, total 8 > 6 available
        # Use: 89 75 10 E9 xx xx xx xx ? 8 bytes, only 6 at site
        print("FALLBACK tip patch via cave search")
        # find CC/NOP cave in text
        cave = None
        for i in range(len(text)-16, 0x1000, -1):
            if text[i:i+16] == b"\x00"*16 or text[i:i+16] == b"\xcc"*16:
                cave = i
                break
        if cave is None:
            for i in range(rs-64, 0x50000, -1):
                if raw[rp0+i:rp0+i+16] == b"\x00"*16:
                    cave = i
                    break
        print("cave", hex(cave) if cave else None)
        if cave:
            # restore original site from pristine
            text0 = bytearray(src_pe.read_bytes()[rp0:rp0+rs])
            # site still int3 in text0
            rel = struct.unpack_from("<i", text0, 0x14a99-tr+1)[0]
            tgt = (0x14a99 - tr) + 5 + rel
            stub = bytearray([0x89, 0x75, 0x10])  # mov [rbp+0x10], esi
            stub += b"\xe9" + struct.pack("<i", tgt - (cave + len(stub) + 5))
            text0[cave:cave+len(stub)] = stub
            text0[0x14a98-tr:0x14a98-tr+6] = b"\xe9" + struct.pack("<i", cave - (0x14a98-tr+5)) + b"\x90"
            # adad fix
            struct.pack_into("<Q", text0, 0x14668-tr+2, 0x8006f844)
            new_raw = bytearray(src_pe.read_bytes())
            new_raw[rp0:rp0+rs] = text0
            dst.write_bytes(new_raw)
            print("wrote cave patch")
        else:
            print("no cave")
else:
    raw[rp0:rp0+len(text)] = text
    dst.write_bytes(raw)
    print("wrote inplace")

# copy shim
import shutil
shutil.copy("build_univ89/w2kshim64.dll", dst.with_name("w2kshim64.dll"))
print("done", dst, dst.stat().st_size)
