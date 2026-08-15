from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_MODE_32
import struct, pathlib
from x86x64.pe import PE32Image

pe = bytearray(pathlib.Path("build_univ228/full.exe").read_bytes())
e = struct.unpack_from("<I", pe, 0x3C)[0]
ns = struct.unpack_from("<H", pe, e+6)[0]
so = struct.unpack_from("<H", pe, e+20)[0]
sec = e+24+so
ib = struct.unpack_from("<Q", pe, e+24+24)[0]
for i in range(ns):
    o = sec+i*40
    if pe[o:o+5] == b".text":
        vs,va,rs,rp = struct.unpack_from("<IIII", pe, o+8); break
code = bytes(pe[rp:rp+rs])
md = Cs(CS_ARCH_X86, CS_MODE_64)

# Show more after 17c6c and search for GetTickCount / execute patterns near 17624
print("==== 17c71+ ====")
for i, insn in enumerate(md.disasm(code[0x17c71-va:0x17d80-va], ib+0x17c71)):
    print(f"  {insn.address:#x}: {insn.mnemonic} {insn.op_str}")
    if i>50: break

# x86 c73b full path
pe32=PE32Image(pathlib.Path(r'C:\Users\win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU\cmd.exe').read_bytes())
sec32,td=pe32.get_text_section()
md32=Cs(CS_ARCH_X86,CS_MODE_32)
print("==== x86 c73b execute path ====")
for i, insn in enumerate(md32.disasm(td[0xc73b-sec32.vaddr:0xc73b-sec32.vaddr+0x80], pe32.image_base+0xc73b)):
    print(f"  {insn.address:08x}: {insn.mnemonic} {insn.op_str}")
    if i>40: break

# Search pe64 for mov [mem], eax after pattern like storing tick count - 22874 global
# Or look for cmp ebx,10000 origin - maybe heal created it
print("==== xrefs to 48900 (E8/E9) ====")
target=0x48900
for i in range(len(code)-5):
    if code[i] in (0xE8,0xE9):
        rel=struct.unpack_from('<i', code, i+1)[0]
        if (va+i+5+rel) & 0xffffffff == target:
            print(f"  {code[i]:02x} at {va+i:#x}")
# also jcc
for i in range(len(code)-6):
    if code[i]==0x0f and code[i+1] in (0x84,0x85,0x8f,0x85):
        rel=struct.unpack_from('<i', code, i+2)[0]
        if (va+i+6+rel) & 0xffffffff == target:
            print(f"  jcc at {va+i:#x}")
