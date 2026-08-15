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

print("==== scan back from 17c31 for calls/prolog ====")
# just disasm a window
start=0x17b40
for insn in md.disasm(code[start-va:0x17c80-va], ib+start):
    print(f"  {insn.address:#x}: {insn.mnemonic} {insn.op_str}")

print("\n==== x86 search 00 00 01 00 imm ====")
pe32=PE32Image(pathlib.Path(r'C:\Users\win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU\cmd.exe').read_bytes())
sec32,td=pe32.get_text_section()
md32=Cs(CS_ARCH_X86,CS_MODE_32)
count=0
for i in range(len(td)-4):
    if td[i:i+4]==bytes([0x00,0x00,0x01,0x00]):
        # check if part of cmp
        for back in range(1,4):
            try:
                insns=list(md32.disasm(td[i-back:i+8], pe32.image_base+sec32.vaddr+i-back, count=1))
            except: continue
            if insns and "0x10000" in insns[0].op_str:
                rva=sec32.vaddr+i-back
                print(f"hit {rva:#x}: {insns[0].mnemonic} {insns[0].op_str}")
                for insn in md32.disasm(td[i-back:i-back+0x28], pe32.image_base+rva):
                    print(f"  {insn.address:08x}: {insn.mnemonic} {insn.op_str}")
                count+=1
                break
        if count>=8: break
print("total shown", count)
