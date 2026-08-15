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

# find push rbp near 17xxx that has large frame
for rva in range(0x17800, 0x17be0):
    if code[rva-va]==0x55 and code[rva-va+1:rva-va+4]==bytes([0x48,0x89,0xe5]):
        print(f"prolog {rva:#x}")
        for i, insn in enumerate(md.disasm(code[rva-va:rva-va+0x60], ib+rva)):
            print(f"  {insn.address:#x}: {insn.mnemonic} {insn.op_str}")
            if i>25: break
        print("---")

# x86: after GEParse-like, cmp ebx,1
pe32=PE32Image(pathlib.Path(r'C:\Users\win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU\cmd.exe').read_bytes())
sec32,td=pe32.get_text_section()
md32=Cs(CS_ARCH_X86,CS_MODE_32)
# call then mov ebx,eax; cmp ebx,1
print("==== x86 mov ebx,eax / cmp ebx,1 near 0xbxxx ====")
for i in range(len(td)-10):
    # 8B D8 = mov ebx,eax; 83 FB 01 = cmp ebx,1
    if td[i:i+5]==bytes([0x8b,0xd8,0x83,0xfb,0x01]) or td[i:i+5]==bytes([0x89,0xc3,0x83,0xfb,0x01]):
        rva=sec32.vaddr+i
        if rva < 0x8000:
            print(f"at {rva:#x}")
            for insn in md32.disasm(td[i-20:i+40], pe32.image_base+rva-20):
                print(f"  {insn.address:08x}: {insn.mnemonic} {insn.op_str}")
