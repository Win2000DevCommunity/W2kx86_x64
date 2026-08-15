import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_MODE_32
# x86 CheckSwitches around 13edc
x86 = pefile.PE(r"C:\Users\win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU\cmd.exe")
md32 = Cs(CS_ARCH_X86, CS_MODE_32)
print("=== x86 AC92 ===")
for i in md32.disasm(x86.get_data(0xAC90, 0x30), 0xAC90):
    print(f"  {i.address:06X}: {i.mnemonic} {i.op_str}")
print("=== x86 13EB0-13F00 (CheckSwitches exit) ===")
for i in md32.disasm(x86.get_data(0x13EB0, 0x60), 0x13EB0):
    print(f"  {i.address:06X}: {i.mnemonic} {i.op_str}")
# who sets 1CF64
text = x86.get_data(0x1000, 0x1A000)
import struct
needle = struct.pack("<I", 0x1CF64)  # absolute? often displ from data
# look for mov [imm],1 with 1CF64
hits=[]
for off in range(len(text)-6):
    if text[off]==0xC7 and text[off+1]==0x05:
        addr=struct.unpack_from("<I", text, off+2)[0]
        if addr==0x1CF64 or (addr&0xFFFF)==0xCF64:
            hits.append((off+0x1000, text[off:off+10].hex()))
    if text[off]==0xA3: # mov [imm],eax
        addr=struct.unpack_from("<I", text, off+1)[0]
        if addr==0x1CF64:
            hits.append((off+0x1000,'a3'))
print("setters", hits[:20])
