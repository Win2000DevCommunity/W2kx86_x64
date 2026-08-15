from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_MODE_32
import struct, pathlib
from x86x64.pe import PE32Image

pe32=PE32Image(pathlib.Path(r'C:\Users\win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU\cmd.exe').read_bytes())
sec32,td=pe32.get_text_section()
md32=Cs(CS_ARCH_X86,CS_MODE_32)
print("==== x86 fbe4 from fd36 (main path) ====")
for i, insn in enumerate(md32.disasm(td[0xfd36-sec32.vaddr:0xfd36-sec32.vaddr+0x120], pe32.image_base+0xfd36)):
    print(f"  {insn.address:08x}: {insn.mnemonic} {insn.op_str}")
    if i>50: break

# How long is fbe4 on x86 until ret?
print("==== scan fbe4 to ret ====")
for insn in md32.disasm(td[0xfbe4-sec32.vaddr:0xfbe4-sec32.vaddr+0x200], pe32.image_base+0xfbe4):
    if insn.mnemonic=='ret':
        print(f"ret at {insn.address:08x} size={insn.address-(pe32.image_base+0xfbe4):#x}")
        break

pe = bytearray(pathlib.Path("build_univ228/cmd_combo.exe").read_bytes())
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

# Search for characteristic: mov word ptr [eax+0x10], bx  / store bx into node+0x10
# pe64 might be: mov word ptr [rax+0x10], bx
print("==== pe64 mov word [r*+0x10], bx ====")
# 66 89 58 10 = mov [rax+10], bx; 66 89 5f 10 = mov [rdi+10],bx
for pat in [bytes.fromhex("66895810"), bytes.fromhex("66895f10"), bytes.fromhex("66895e10"),
            bytes.fromhex("66895910"), bytes.fromhex("66448958")]:
    start=0; n=0
    while n<10:
        k=code.find(pat, start)
        if k<0: break
        print(f"  {pat.hex()} at {va+k:#x}")
        for insn in md.disasm(code[k:k+0x30], ib+va+k):
            print(f"    {insn.address:#x}: {insn.mnemonic} {insn.op_str}")
            if insn.address > ib+va+k+0x20: break
        start=k+1; n+=1

# Also search jmp to 48919 (bogus epi shared)
print("==== jmps to 48919 ====")
tgt=0x48919
for i in range(len(code)-5):
    if code[i]==0xE9:
        rel=struct.unpack_from('<i', code, i+1)[0]
        if (va+i+5+rel)&0xffffffff==tgt:
            print(f"  jmp at {va+i:#x}")
