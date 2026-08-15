import pefile, struct
from capstone import Cs, CS_ARCH_X86, CS_MODE_32
x86 = pefile.PE(r"C:\Users\win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU\cmd.exe")
# find "exit" string and eExit handler - or search push before call ac92
text = x86.get_data(0x1000, 0x1A000)
md = Cs(CS_ARCH_X86, CS_MODE_32)
# all call ac92 with context
target=0xAC92
for off in range(len(text)-5):
    if text[off]!=0xE8: continue
    rel=struct.unpack_from("<i", text, off+1)[0]
    if off+0x1000+5+rel!=target: continue
    rva=off+0x1000
    # disasm 16 bytes before
    print(f"\ncall AC92 from {rva:#x}")
    start=max(0, off-20)
    for i in md.disasm(text[start:off+5], 0x1000+start):
        print(f"  {i.address:06X}: {i.mnemonic} {i.op_str}")
