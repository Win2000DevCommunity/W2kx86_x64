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
print("==== 48900 ====")
for i, insn in enumerate(md.disasm(code[0x48900-va:0x48900-va+0xa0], ib+0x48900)):
    print(f"  {insn.address:#x}: {insn.mnemonic} {insn.op_str}")
    if i>35: break

print("==== 1c69b+ (after FF31 setup in 1c5f8) ====")
for i, insn in enumerate(md.disasm(code[0x1c69b-va:0x1c69b-va+0x80], ib+0x1c69b)):
    print(f"  {insn.address:#x}: {insn.mnemonic} {insn.op_str}")
    if i>40: break

# x86: find caller of f4eb / ecmp return
SRC=pathlib.Path(r'C:\Users\win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU\cmd.exe')
pe32=PE32Image(SRC.read_bytes())
sec32,td=pe32.get_text_section()
md32=Cs(CS_ARCH_X86,CS_MODE_32)
# search for call f4eb
target = pe32.image_base + 0xf4eb
print("==== x86 callers of f4eb ====")
for i in range(len(td)-5):
    if td[i]==0xE8:
        rel=struct.unpack_from('<i', td, i+1)[0]
        if (sec32.vaddr+i+5+rel) == 0xf4eb:
            site=sec32.vaddr+i
            print(f"call at {site:#x}")
            for insn in md32.disasm(td[site-sec32.vaddr:site-sec32.vaddr+0x40], pe32.image_base+site):
                print(f"  {insn.address:08x}: {insn.mnemonic} {insn.op_str}")
                if insn.address > pe32.image_base+site+0x30: break
