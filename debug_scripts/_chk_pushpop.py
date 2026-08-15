from capstone import Cs, CS_ARCH_X86, CS_MODE_64
import struct, pathlib
pe = bytearray(pathlib.Path("build_univ229/cmd_diam.exe").read_bytes())
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
print("All push/pop in fn:")
for insn in md.disasm(code[0x249e8-va:0x24e17-va], ib+0x249e8):
    if insn.mnemonic in ("push","pop"):
        print(f"  {insn.address:#x}: {insn.mnemonic} {insn.op_str}")
# x86 original
from x86x64.pe import PE32Image
pe32=PE32Image(pathlib.Path(r'C:\Users\win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU\cmd.exe').read_bytes())
sec32,td=pe32.get_text_section()
md32=Cs(CS_ARCH_X86,CS_MODE_32)
# find x86 fn containing similar - search for push 0x... charset ref
# data rva for 58628-58000=0x628 in .data - x86 base
# search call pattern with delimiter
print("\nsearch x86 for mov di,[imm] near sub esp,0x1c")
for off in range(0, len(td)-10):
    # 66 8B 3D = mov di, [imm32]
    if td[off:off+2]==b'\x66\x8b' and td[off+2]==0x3d:
        imm=struct.unpack_from("<I",td,off+3)[0]
        if (imm & 0xffff)==0x8628 or (imm & 0xfff)==0x628:
            print(f"found at {sec32.vaddr+off:#x} imm={imm:#x}")
            base=max(0,off-0x40)
            for insn in md32.disasm(td[base:off+0x30], pe32.image_base+sec32.vaddr+base):
                print(f"  {insn.address:08x}: {insn.mnemonic} {insn.op_str}")
            break
