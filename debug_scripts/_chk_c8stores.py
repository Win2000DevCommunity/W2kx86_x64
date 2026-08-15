import struct
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
import pefile
pe=pefile.PE("build_univ212/cmd_pure.exe")
pe_data=open("build_univ212/cmd_pure.exe","rb").read()
for s in pe.sections:
    if s.Name.startswith(b".text"):
        text=pe_data[s.PointerToRawData:s.PointerToRawData+s.SizeOfRawData]
md=Cs(CS_ARCH_X86,CS_MODE_64)
c8=struct.pack("<Q", 0x800588d8)
idx=0
while True:
    j=text.find(b"\x49\xbb"+c8, idx)
    if j<0: break
    insns=list(md.disasm(text[j:j+28], 0x80001000+j))
    for ins in insns[:5]:
        if ins.mnemonic=="mov" and ins.op_str.startswith("dword ptr [r11]"):
            print("%#x:" % (0x1000+j), "; ".join("%s %s" % (x.mnemonic,x.op_str) for x in insns[:5]))
            break
        if ins.mnemonic=="mov" and ins.op_str.startswith("qword ptr [r11]"):
            print("%#x: QWORD" % (0x1000+j), "; ".join("%s %s" % (x.mnemonic,x.op_str) for x in insns[:5]))
            break
    idx=j+1
# also 41 89 03 / 41 89 1b etc after movabs
print("--- pattern 49 bb c8.. / 41 89 ---")
idx=0
while True:
    j=text.find(b"\x49\xbb"+c8, idx)
    if j<0: break
    after=text[j+10:j+16]
    if after[:2] in (b"\x41\x89", b"\x45\x89", b"\x4c\x89", b"\x49\x89"):
        insns=list(md.disasm(text[j:j+20], 0x80001000+j))
        print("%#x" % (0x1000+j), "; ".join("%s %s" % (x.mnemonic,x.op_str) for x in insns[:3]), "raw", after.hex())
    idx=j+1
