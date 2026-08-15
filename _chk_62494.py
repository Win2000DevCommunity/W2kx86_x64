import pefile
pe = pefile.PE("build_univ258/cmd_probe_jcc.exe")
print("ImageBase", hex(pe.OPTIONAL_HEADER.ImageBase))
print("SizeOfImage", hex(pe.OPTIONAL_HEADER.SizeOfImage))
for s in pe.sections:
    print(s.Name, "VA", hex(s.VirtualAddress), "VSz", hex(s.Misc_VirtualSize), "end", hex(s.VirtualAddress+s.Misc_VirtualSize))
# 62494 - which section?
rva=0x62494
for s in pe.sections:
  if s.VirtualAddress <= rva < s.VirtualAddress+max(s.Misc_VirtualSize,s.SizeOfRawData):
    print("62494 in", s.Name)
# x86 4ad26494 -> rva 0x26494
print("x86 global 26494")
x86=pefile.PE(r"C:\Users\win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU\cmd.exe")
for s in x86.sections:
  print("x86", s.Name, hex(s.VirtualAddress), hex(s.Misc_VirtualSize))
