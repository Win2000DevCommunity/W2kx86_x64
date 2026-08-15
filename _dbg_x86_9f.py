import struct, pathlib
from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64

src = pathlib.Path(r"C:\Users\win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU\cmd.exe").read_bytes()
e = struct.unpack_from("<I", src, 0x3C)[0]
opt = e+24
ib = struct.unpack_from("<I", src, opt+28)[0]
nsec = struct.unpack_from("<H", src, e+6)[0]
szopt = struct.unpack_from("<H", src, e+20)[0]
soff = e+24+szopt
for i in range(nsec):
    o=soff+i*40
    name=src[o:o+8].split(b"\0",1)[0]
    vsz,va,rsz,raw=struct.unpack_from("<IIII", src, o+8)
    if name.startswith(b".text"):
        text_va, text_raw, text_rsz = va, raw, rsz
        break
text = src[text_raw:text_raw+text_rsz]
md=Cs(CS_ARCH_X86, CS_MODE_32)

def dis(rva, n=50):
    fo=rva-text_va
    print(f"\n=== x86 linear from {rva:#x} ===")
    for insn in md.disasm(text[fo:fo+120], ib+rva):
        print(f"  {insn.address:#x}: {insn.mnemonic} {insn.op_str}")
        n-=1
        if n<=0: break

dis(0x9ee0)
# IAT slots
print("\nIAT 0x11d8, 0x11dc, 0x10a4, 0x1204 names from pe imports...")
# parse imports roughly - or use pe file
import pefile
pe=pefile.PE(data=src)
slots={}
for e in pe.DIRECTORY_ENTRY_IMPORT:
    for imp in e.imports:
        if imp.address:
            slots[imp.address]= (e.dll.decode(), imp.name.decode() if imp.name else imp.ordinal)
for va in [0x4ad011d8, 0x4ad011dc, 0x4ad010a4, 0x4ad01204]:
    print(hex(va), slots.get(va))

# PE64 side disasm 0x11900
pe64=pathlib.Path("build_univ53/cmd_heal2.exe").read_bytes()
e2=struct.unpack_from("<I", pe64, 0x3C)[0]
opt2=e2+24
ib2=struct.unpack_from("<Q", pe64, opt2+24)[0]
nsec2=struct.unpack_from("<H", pe64, e2+6)[0]
szopt2=struct.unpack_from("<H", pe64, e2+20)[0]
soff2=e2+24+szopt2
for i in range(nsec2):
    o=soff2+i*40
    name=pe64[o:o+8].split(b"\0",1)[0]
    vsz,va,rsz,raw=struct.unpack_from("<IIII", pe64, o+8)
    if name.startswith(b".text"):
        tva,traw,trsz=va,raw,rsz
        break
t64=pe64[traw:traw+trsz]
md64=Cs(CS_ARCH_X86, CS_MODE_64)
print("\n=== pe64 from 0x118f0 ===")
fo=0x118f0-tva
for insn in md64.disasm(t64[fo:fo+0x100], ib2+0x118f0):
    print(f"  {insn.address:#x}: {insn.mnemonic} {insn.op_str}")
    if insn.address > ib2+0x11a20: break

# What is at IAT 93420 / 93428 in pe64
print("\nPE64 IAT around 93420:")
# idata
for i in range(nsec2):
    o=soff2+i*40
    name=pe64[o:o+8].split(b"\0",1)[0]
    vsz,va,rsz,raw=struct.unpack_from("<IIII", pe64, o+8)
    if name.startswith(b".idata"):
        idata=pe64[raw:raw+rsz]; iva=va; break
# can't resolve runtime IAT from file easily - parse import names from idata
pe64p=pefile.PE(data=pe64)
for e in pe64p.DIRECTORY_ENTRY_IMPORT:
    for imp in e.imports:
        if imp.address in (0x80093420, 0x80093428, 0x80093470, 0x93420, 0x93428, 0x93470) or (imp.address and (imp.address & 0xfffff) in (0x93420, 0x93428, 0x93470)):
            print(hex(imp.address), e.dll, imp.name)
# print all msvcrt near
for e in pe64p.DIRECTORY_ENTRY_IMPORT:
    if b"msvcrt" in e.dll.lower() or b"ucrt" in e.dll.lower() or b"shim" in e.dll.lower() or b"ntdll" in e.dll.lower():
        for imp in e.imports:
            if imp.address and 0x93400 <= (imp.address - ib2) <= 0x93500:
                print(hex(imp.address), (imp.address-ib2), e.dll, imp.name)
