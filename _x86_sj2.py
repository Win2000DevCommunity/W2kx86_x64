import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_32
x86=pefile.PE(r"C:\Users\win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU\cmd.exe")
for e in x86.DIRECTORY_ENTRY_IMPORT:
  for imp in e.imports:
    if imp.name and (b'setjmp' in imp.name or b'longjmp' in imp.name):
      print(hex(imp.address-x86.OPTIONAL_HEADER.ImageBase), imp.name, e.dll)

# search push imm fb40 or fb80
text=x86.get_memory_mapped_image()
import struct
for rva_data, name in [(0x1fb40,'fb40'), (0x1fb80,'fb80')]:
  va=x86.OPTIONAL_HEADER.ImageBase+rva_data
  # 68 xx xx xx xx push imm32
  pat=b'\x68'+struct.pack('<I', va)
  hits=[]
  off=0
  while True:
    i=text.find(pat, off)
    if i<0: break
    hits.append(i); off=i+1
  print(name, 'push imm', [hex(h) for h in hits[:15]], 'n', len(hits))
