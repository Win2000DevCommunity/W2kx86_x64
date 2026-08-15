import struct, pathlib
from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_MODE_32
pe=pathlib.Path("build_univ53/cmd_heal6.exe").read_bytes()
e=struct.unpack_from("<I",pe,0x3C)[0]; ib=struct.unpack_from("<Q",pe,e+24+24)[0]
nsec=struct.unpack_from("<H",pe,e+6)[0]; sz=struct.unpack_from("<H",pe,e+20)[0]; so=e+24+sz
for i in range(nsec):
    o=so+i*40; name=pe[o:o+8].split(b"\0",1)[0]
    vsz,va,rsz,raw=struct.unpack_from("<IIII",pe,o+8)
    if name.startswith(b".text"):
        tva,traw,t=va,raw,pe[raw:raw+rsz]; break
md=Cs(CS_ARCH_X86,CS_MODE_64)
print("=== pe64 277f0 ===")
fo=0x277f0-tva
for insn in md.disasm(t[fo:fo+80], ib+0x277f0):
    print(f"  {insn.address:#x}: {insn.mnemonic} {insn.op_str}")
rmap={}
for line in open("build_univ53/rva.txt"):
    a,b=line.split(); rmap[int(a,16)]=int(b,16)
print("14fe4 map", hex(rmap.get(0x14fe4,0)))
print("14fec map", hex(rmap.get(0x14fec,0)), hex(rmap.get(0x14ff2,0)), hex(rmap.get(0x14ff6,0)))
# IAT 11ec and 1078 names
import pefile
p=pefile.PE(data=pathlib.Path(r"C:\Users\win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU\cmd.exe").read_bytes())
for e in p.DIRECTORY_ENTRY_IMPORT:
  for imp in e.imports:
    if imp.address in (0x4ad011ec, 0x4ad01078):
      print(hex(imp.address), e.dll, imp.name)