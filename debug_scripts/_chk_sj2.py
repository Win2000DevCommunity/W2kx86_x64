import struct
from pathlib import Path
from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64
from tools.audit_calls import read_text_section, load_map

src=Path(r"C:\Users\win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU\cmd.exe").read_bytes()
e=struct.unpack_from("<I",src,0x3c)[0]
num=struct.unpack_from("<H",src,e+6)[0]; soh=struct.unpack_from("<H",src,e+20)[0]; sec=e+24+soh
for i in range(num):
    o=sec+i*40
    if src[o:o+5]==b".text":
        va,rs,rp=struct.unpack_from("<III",src,o+12); text=src[rp:rp+rs]; text_rva=va; break
base=struct.unpack_from("<I",src,e+24+28)[0]
md=Cs(CS_ARCH_X86, CS_MODE_32)
print("=== x86 setjmp fb40 site ===")
for insn in md.disasm(text[0xef40-text_rva:0xef90-text_rva], base+0xef40, count=30):
    print(f"{insn.address-base:#07x}  {insn.mnemonic} {insn.op_str}")

# x64 translation of this site
rmap=load_map(Path("build_univ11/rva.txt"))
trva,data,_=read_text_section(Path("build_univ11/cmd_pure.exe").read_bytes())
md64=Cs(CS_ARCH_X86, CS_MODE_64)
# find map for 0xef63/ef64
for o in range(0xef50, 0xef80):
    if o in rmap:
        print(f"map {o:#x} -> {rmap[o]:#x}")
ent=rmap.get(0xef5b) or rmap.get(0xef63) or rmap.get(0xef50)
# search for movabs to 0x80060b40
pat=struct.pack("<Q", 0x80060b40)
idx=0
print("\n=== x64 refs to 0x80060b40 ===")
while True:
    i=data.find(pat, idx)
    if i<0: break
    # back up to find insn
    print(f"  at {trva+i:#x}, context:")
    start=max(0,i-8)
    for ins in md64.disasm(data[start:i+16], trva+start, count=5):
        print(f"    {ins.address:#07x}  {ins.mnemonic} {ins.op_str}")
    idx=i+1
