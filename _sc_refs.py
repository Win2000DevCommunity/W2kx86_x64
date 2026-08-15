import pefile, struct
from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64
x86 = pefile.PE(r"C:\Users\win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU\cmd.exe")
text = x86.get_data(0x1000, 0x1A000)
# find all refs to 0x4ad1cf64
target = 0x4ad1cf64
for off in range(len(text)-6):
    # C7 05 addr imm32
    if text[off]==0xC7 and text[off+1]==0x05:
        addr=struct.unpack_from("<I", text, off+2)[0]
        if addr==target:
            imm=struct.unpack_from("<I", text, off+6)[0]
            print(f"set {off+0x1000:#x}: mov [SingleCommand], {imm}")
    if text[off]==0x833D: # wrong
        pass
    if text[off]==0x83 and text[off+1]==0x3D:
        addr=struct.unpack_from("<I", text, off+2)[0]
        if addr==target:
            print(f"cmp {off+0x1000:#x}: {text[off:off+7].hex()}")
    if text[off]==0xA1:
        addr=struct.unpack_from("<I", text, off+1)[0]
        if addr==target:
            print(f"mov eax,[] {off+0x1000:#x}")
    if text[off]==0x8B and text[off+1] in (0x0D,0x15,0x1D,0x25,0x2D,0x35,0x3D):
        addr=struct.unpack_from("<I", text, off+2)[0]
        if addr==target:
            print(f"mov r,[] {off+0x1000:#x} {text[off:off+6].hex()}")

# pe64: find mov dword [r11], 1 near 58F64 loads
pe = pefile.PE("build_univ257/cmd_pure.exe")
md = Cs(CS_ARCH_X86, CS_MODE_64)
text64 = pe.get_data(0x1000, 0x57000)
# scan for movabs ... 80058F64 followed soon by mov dword [r11], 1
import re
for m in re.finditer(struct.pack("<Q", 0x80058F64), text64):
    at = m.start()+0x1000
    blob = pe.get_data(at-8, 0x30)
    for i in md.disasm(blob, 0x80000000+at-8):
        if "58f64" in i.op_str.lower() or (i.address>=0x80000000+at and i.address < 0x80000000+at+0x28):
            pass
    # print short context
    print(f"\n--- pe64 ref {at:#x} ---")
    for i in md.disasm(pe.get_data(at-0x10, 0x40), 0x80000000+at-0x10):
        mark = " <<" if abs(i.address - (0x80000000+at)) < 2 else ""
        print(f"  {i.address-0x80000000:06X}: {i.mnemonic} {i.op_str}{mark}")
