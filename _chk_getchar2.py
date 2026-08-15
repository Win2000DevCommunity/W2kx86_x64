import struct
from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64

pe=open(r"C:\Users\win2000\Desktop\univ88\cmd_pure.exe","rb").read()
e=struct.unpack_from("<I",pe,0x3c)[0]
n=struct.unpack_from("<H",pe,e+6)[0]; opt=struct.unpack_from("<H",pe,e+20)[0]; s0=e+24+opt
for i in range(n):
    o=s0+i*40
    if pe[o:o+5]==b".text":
        vs,va,rs,rp=struct.unpack_from("<IIII",pe,o+8); text=pe[rp:rp+rs]; tva=va; break

md=Cs(CS_ARCH_X86, CS_MODE_64)
print("=== full pe64 getchar ===")
off=0x55ef8-tva
for insn in md.disasm(text[off:off+0xc0], 0x80000000+0x55ef8):
    print(f"  {insn.address:#x}  {insn.bytes.hex():28}  {insn.mnemonic} {insn.op_str}")

# Check remaps of the two globals
# x86 0x4ad1fbc8 and 0x4ad1cfa8
old_base=0x4ad00000
# find pe64 values for these
for old in (0x4ad1fbc8, 0x4ad1cfa8, 0x4ad1fbc4, 0x4ad1fbe0, 0x4ad1fbe2):
    rva=old-old_base
    print(f"old {old:#x} rva {rva:#x} identity {0x80000000+rva:#x}")

# dump runtime: need live. Also check if 0x6cbc8 content in file
for name_i in range(n):
    o=s0+name_i*40
    name=pe[o:o+8].split(b'\0')[0]
    vs,va,rs,rp=struct.unpack_from("<IIII",pe,o+8)
    if name==b'.data':
        for rva in (0x6cbc8, 0x6cfa8, 0x1fbc8, 0x1cfa8):
            if va <= rva < va+max(vs,rs):
                off=rp+(rva-va)
                print(f"file .data {rva:#x}:", pe[off:off+8].hex() if off+8<=len(pe) else "oob")
            else:
                # try as old rva in new data layout
                # old data rva 0x1c000 -> new 0x69000, delta
                old_data=0x1c000
                new_data=0x69000
                if rva >= 0x1c000:
                    nrva=new_data+(rva-old_data)
                    if va <= nrva < va+vs:
                        off=rp+(nrva-va)
                        print(f"remap {rva:#x}->{nrva:#x}:", pe[off:off+8].hex())
