import os, shutil, struct, sys
os.environ["PURE"] = "1"
sys.path.insert(0, ".")
from pathlib import Path
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from x86x64.pe.pe32 import PE32Image
from x86x64.translator import Win2000Translator

src = Path(r"C:\Users\win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU\cmd.exe")
dst_dir = Path(r"C:\Users\win2000\Desktop\univ87h")
dst_dir.mkdir(exist_ok=True)
shutil.copy(r"C:\Users\win2000\Desktop\univ87\cmd_pure.exe", dst_dir / "cmd_pure.exe")
shutil.copy(r"C:\Users\win2000\Desktop\univ87\w2kshim64.dll", dst_dir / "w2kshim64.dll")

pe = PE32Image(src.read_bytes())
raw = bytearray((dst_dir / "cmd_pure.exe").read_bytes())
e = struct.unpack_from("<I", raw, 0x3C)[0]
ns = struct.unpack_from("<H", raw, e + 6)[0]
so = struct.unpack_from("<H", raw, e + 20)[0]
sec = e + 24 + so
tr = rp0 = rsz = None
for i in range(ns):
    o = sec + i * 40
    name = raw[o:o + 8].split(b"\x00")[0].decode()
    vs, va, rs, rp = struct.unpack_from("<IIII", raw, o + 8)
    if name == ".text":
        tr, rp0, rsz = va, rp, rs
text = bytearray(raw[rp0:rp0 + rsz])

rmap = {}
for line in Path("build_univ84/rva.txt").read_text().splitlines():
    a = line.split()
    if len(a) == 2:
        rmap[int(a[0], 16)] = int(a[1], 16)

st = next(s for s in pe.sections if s["name"].startswith(".text"))
text_src = bytes(pe.raw[st["raw_ptr"]:st["raw_ptr"] + st["raw_sz"]])
text_rva = st["vaddr"]

t = Win2000Translator(pe, win10_test_shim=True, source_path=str(src))
t._cmd_no_hacks = True
t.new_base = 0x80000000
t._old_to_new_section = {0x1000: 0x1000, 0x1c000: 0x69000, 0x2a000: 0x77000}
t._pure_heal_text = text_src
t._pure_heal_text_rva = text_rva
t.rva_map = rmap

print("reloc load", hex(t._relocate_imm(0x4ad264c0, 0, 0)))
print("reloc push", hex(t._relocate_imm(0x4ad01d28, 0, 0)))
print("before", text[0x28938 - tr:0x28957 - tr].hex())

n1 = t._pure_reanchor_data_movabs_from_x86_pushes(text, rmap, text_src, text_rva)
print("reanchor", n1)
n2 = t._pure_fix_shifted_data_movabs(text, text_src, text_rva)
print("shifted", n2)
n3 = t._pure_resync_code_pointer_movabs(text, rmap, text_src, text_rva)
print("codeptr", n3)
n4 = t._pure_nop_orphan_int3(text)
print("dead-nop", n4)

print("after", text[0x28938 - tr:0x28957 - tr].hex())
md = Cs(CS_ARCH_X86, CS_MODE_64)
for i in md.disasm(text[0x28938 - tr:0x28970 - tr], 0x80000000 + 0x28938):
    print(f"  {i.address:#x}: {i.mnemonic} {i.op_str}")

raw[rp0:rp0 + rsz] = text
(dst_dir / "cmd_pure.exe").write_bytes(raw)
print("wrote", dst_dir / "cmd_pure.exe")