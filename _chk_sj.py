import struct
from pathlib import Path
from capstone import Cs, CS_ARCH_X86, CS_MODE_32

# IAT names for 0x89ef8 and 0x89ed8
pe=Path("build_univ11/cmd_pure.exe").read_bytes()
e=struct.unpack_from("<I",pe,0x3c)[0]
num=struct.unpack_from("<H",pe,e+6)[0]; soh=struct.unpack_from("<H",pe,e+20)[0]; opt=e+24; sec=e+24+soh
def rva_to_off(rva):
    for i in range(num):
        o=sec+i*40
        vs,va,rs,rp=struct.unpack_from("<IIII",pe,o+8)
        if va<=rva<va+max(vs,rs): return rp+(rva-va)
    return None
idd=struct.unpack_from("<I",pe,opt+120)[0]; off=rva_to_off(idd)
want={0x89ef8, 0x89ed8}
while True:
    ilt,_,_,name_rva,iat=struct.unpack_from("<IIIII",pe,off)
    if not name_rva: break
    dll=pe[rva_to_off(name_rva):].split(b"\0")[0]
    iat_off=rva_to_off(iat); idx=0
    while True:
        if struct.unpack_from("<Q",pe,iat_off+idx*8)[0]==0: break
        slot=iat+idx*8
        if slot in want:
            hint=struct.unpack_from("<Q",pe,rva_to_off(ilt or iat)+idx*8)[0]&0x7fffffffffffffff
            print(hex(slot), dll, pe[rva_to_off(hint)+2:].split(b"\0")[0])
        idx+=1
        if idx>500: break
    off+=20

# x86 at 0xadd9 (called with push [esp+4]; push [global])
src=Path(r"C:\Users\win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU\cmd.exe").read_bytes()
e=struct.unpack_from("<I",src,0x3c)[0]
num=struct.unpack_from("<H",src,e+6)[0]; soh=struct.unpack_from("<H",src,e+20)[0]; sec=e+24+soh
for i in range(num):
    o=sec+i*40
    if src[o:o+5]==b".text":
        va,rs,rp=struct.unpack_from("<III",src,o+12); text=src[rp:rp+rs]; text_rva=va; break
base=struct.unpack_from("<I",src,e+24+28)[0]
md=Cs(CS_ARCH_X86, CS_MODE_32)
print("\n=== x86 0xadd9 ===")
for insn in md.disasm(text[0xadd9-text_rva:0xae80-text_rva], base+0xadd9, count=35):
    print(f"{insn.address-base:#07x}  {insn.mnemonic} {insn.op_str}")

# setjmp sites around fb40 / fb80
print("\n=== x86 near setjmp buf uses ===")
for rva in (0xe540, 0xe600, 0xf5d0, 0xf640):
    print(f"--- {rva:#x} ---")
    for insn in md.disasm(text[rva-text_rva:rva-text_rva+0x40], base+rva, count=15):
        print(f"  {insn.address-base:#07x}  {insn.mnemonic} {insn.op_str}")
