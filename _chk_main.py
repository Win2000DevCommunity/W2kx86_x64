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

# find function start before 17c31 - scan back for push rbp
for back in range(0, 0x200):
    at = 0x17c31 - back
    if code[at-va]==0x55 and code[at-va+1:at-va+4]==bytes([0x48,0x89,0xe5]):
        print(f"frame prologue at {at:#x}")
        for i, insn in enumerate(md.disasm(code[at-va:at-va+0x80], ib+at)):
            print(f"  {insn.address:#x}: {insn.mnemonic} {insn.op_str}")
            if i>35: break
        break

# x86 cmp 10000 with different regs
pe32=PE32Image(pathlib.Path(r'C:\Users\win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU\cmd.exe').read_bytes())
sec32,td=pe32.get_text_section()
md32=Cs(CS_ARCH_X86,CS_MODE_32)
print("==== x86 cmp *,0x10000 ====")
for i in range(len(td)-6):
    if td[i]==0x81 and td[i+2:i+6]==bytes([0x00,0x00,0x01,0x00]):
        rva=sec32.vaddr+i
        # only near parse-ish
        if 0x1000 <= rva <= 0x5000 or 0xa000 <= rva <= 0xc000:
            print(f"at {rva:#x} bytes {td[i:i+6].hex()}")
            for insn in md32.disasm(td[max(0,i-10):i+0x30], pe32.image_base+rva-10):
                print(f"  {insn.address:08x}: {insn.mnemonic} {insn.op_str}")
