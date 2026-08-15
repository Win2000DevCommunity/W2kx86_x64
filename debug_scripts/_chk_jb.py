import struct
from pathlib import Path
from capstone import Cs, CS_ARCH_X86, CS_MODE_32

src=Path(r"C:\Users\win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU\cmd.exe").read_bytes()
e=struct.unpack_from("<I",src,0x3c)[0]
num=struct.unpack_from("<H",src,e+6)[0]; soh=struct.unpack_from("<H",src,e+20)[0]; sec=e+24+soh
for i in range(num):
    o=sec+i*40
    if src[o:o+5]==b".text":
        va,rs,rp=struct.unpack_from("<III",src,o+12); text=src[rp:rp+rs]; text_rva=va; break
base=struct.unpack_from("<I",src,e+24+28)[0]
md=Cs(CS_ARCH_X86, CS_MODE_32); md.detail=True

# Find all refs to fb40 and fb80
for name, addr in [("fb40", 0x4ad1fb40), ("fb80", 0x4ad1fb80)]:
    print(f"\n=== refs to {name} ===")
    needle=struct.pack("<I", addr)
    # search in .text
    pos=0
    while True:
        i=text.find(needle, pos)
        if i<0: break
        rva=text_rva+i
        # disasm a bit before
        start=max(0,i-12)
        print(f"  at {rva:#x}:")
        for insn in md.disasm(text[start:i+8], base+text_rva+start, count=6):
            mark=" ***" if needle in insn.bytes else ""
            print(f"    {insn.address-base:#07x}  {insn.mnemonic} {insn.op_str}{mark}")
        pos=i+1

# Also what is call 0x4ad1a766 - setjmp?
print("\n=== x86 0x1a766 ===")
for insn in md.disasm(text[0x1a766-text_rva:0x1a790-text_rva], base+0x1a766, count=15):
    print(f"  {insn.address-base:#07x}  {insn.bytes.hex()} {insn.mnemonic} {insn.op_str}")
