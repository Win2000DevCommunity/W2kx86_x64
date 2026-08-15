import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_32
x86 = pefile.PE(r"C:\Users\win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU\cmd.exe")
md=Cs(CS_ARCH_X86,CS_MODE_32)
ib=x86.OPTIONAL_HEADER.ImageBase
# table at 0x13e4 in mapped image - that's file offset or VA?
# get_memory_mapped_image uses VA from 0
print('ImageBase', hex(ib))
# find refs to table VA = ib+0x13e4? or section
# Actually needle found at 0x13e4 in mapped image = RVA 0x13e4
table_va = ib + 0x13e4
print('table VA', hex(table_va))
# find push imm of table or mov reg, imm
raw = x86.get_memory_mapped_image()
# search for push table (68 xx) or mov eax, table
pat = struct.pack('<I', table_va) if False else None
import struct
pat = struct.pack('<I', table_va)
hits=[]
off=0
while True:
    i=raw.find(pat, off)
    if i<0: break
    hits.append(i); off=i+1
print('direct VA refs', [hex(h) for h in hits[:30]], 'count', len(hits))
# Also RVA-relative in .text as 0x4ad013e4 style - data is at 4ad013e4 if imagebase 4ad00000
# Win2000 cmd image base?
print('ib', hex(ib))
# data section VA for 0x13e4 - check sections
for s in x86.sections:
    print(s.Name, hex(s.VirtualAddress), hex(s.Misc_VirtualSize))
