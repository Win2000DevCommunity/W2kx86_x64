import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_32
x86 = pefile.PE(r"C:\Users\win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU\cmd.exe")
# WaitForSingleObject IAT
for e in x86.DIRECTORY_ENTRY_IMPORT:
    for i in e.imports:
        if i.name and b"WaitForSingleObject" in i.name:
            print("WFS", hex(i.address), i.name)
        if i.name and b"longjmp" in i.name:
            print("LJ", hex(i.address), i.name)
# find call [WaitForSingleObject] near fae0 refs - x86 fae0 at 1FAE0, data base 1C000
# search ff15 to WFS
import struct
wfs_iat = None
for e in x86.DIRECTORY_ENTRY_IMPORT:
    for i in e.imports:
        if i.name == b"WaitForSingleObject":
            wfs_iat = i.address
print("wfs_iat", hex(wfs_iat) if wfs_iat else None)
text = x86.get_data(0x1000, 0x1A000)
if wfs_iat:
    for off in range(len(text)-6):
        if text[off]==0xFF and text[off+1]==0x15:
            addr=struct.unpack_from("<I", text, off+2)[0]
            if addr==wfs_iat:
                rva=off+0x1000
                print(f"\ncall WFS at {rva:#x}")
                md=Cs(CS_ARCH_X86, CS_MODE_32)
                for i in md.disasm(text[off-30:off+10], rva-30):
                    print(f"  {i.address:06X}: {i.mnemonic} {i.op_str}")
