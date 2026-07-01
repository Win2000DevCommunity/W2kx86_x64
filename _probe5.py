import pefile, struct
from capstone import Cs, CS_ARCH_X86, CS_MODE_32
# original cmd
src=pefile.PE(r"C:\Users\Win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU\cmd.exe")
text=None
for s in src.sections:
    nm=s.Name.rstrip(b"\x00")
    if nm==b".text":
        text_rva=s.VirtualAddress
        text=src.get_memory_mapped_image()[text_rva:text_rva+s.Misc_VirtualSize]
print("text_rva",hex(text_rva),"len",hex(len(text)))
F=0xa4e7; fo=F-text_rva
print("fo",hex(fo),"head", text[fo:fo+10].hex())
imm=int.from_bytes(text[fo+1:fo+5],"little")
rel=int.from_bytes(text[fo+6:fo+10],"little",signed=True)
ct=(F+10+rel)&0xFFFFFFFF
print("imm",hex(imm),"call_tgt",hex(ct))
print("probe bytes @call_tgt:", src.get_memory_mapped_image()[ct:ct+6].hex())
