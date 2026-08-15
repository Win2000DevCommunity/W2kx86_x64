from capstone import Cs, CS_ARCH_X86, CS_MODE_32
import struct, pathlib
from x86x64.pe import PE32Image
pe32=PE32Image(pathlib.Path(r'C:\Users\win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU\cmd.exe').read_bytes())
raw=pathlib.Path(r'C:\Users\win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU\cmd.exe').read_bytes()
# find utf16 =,; in file
needle="=,;".encode("utf-16-le")
idx=0; hits=[]
while True:
    j=raw.find(needle, idx)
    if j<0: break
    hits.append(j); idx=j+1
print("file offs", hits[:5])
# map to VA via sections
e=struct.unpack_from("<I",raw,0x3C)[0]
ns=struct.unpack_from("<H",raw,e+6)[0]; so=struct.unpack_from("<H",raw,e+20)[0]; sec=e+24+so
for j in hits[:3]:
    for i in range(ns):
        o=sec+i*40
        name=raw[o:o+8].split(b"\0")[0]
        vs,va,rs,rp=struct.unpack_from("<IIII",raw,o+8)
        if rp <= j < rp+rs:
            rva=va+(j-rp)
            print(name, "rva", hex(rva), "va", hex(pe32.image_base+rva))
            target_va=pe32.image_base+rva
            break
sec32,td=pe32.get_text_section()
md32=Cs(CS_ARCH_X86,CS_MODE_32)
# search for immediate target_va in text
imm=struct.pack("<I", target_va)
off=0; found=0
while found<3:
    j=td.find(imm, off)
    if j<0: break
    # show context
    start=max(0,j-0x30)
    print(f"\nimm at text+{j:#x} rva={sec32.vaddr+j:#x}")
    for insn in md32.disasm(td[start:j+8], pe32.image_base+sec32.vaddr+start):
        print(f"  {insn.address:08x}: {insn.mnemonic} {insn.op_str}")
    off=j+1; found+=1
