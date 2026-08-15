import struct, pathlib
from capstone import Cs, CS_ARCH_X86, CS_MODE_32
md=Cs(CS_ARCH_X86, CS_MODE_32)
x86=pathlib.Path(r"C:\Users\win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU\cmd.exe").read_bytes()
e=struct.unpack_from("<I",x86,0x3C)[0]
ib=struct.unpack_from("<I",x86,e+0x34)[0]
ns=struct.unpack_from("<H",x86,e+6)[0]; so=struct.unpack_from("<H",x86,e+20)[0]; sec=e+24+so
for i in range(ns):
    o=sec+i*40
    if x86[o:o+5]==b".text":
        vs,va,rs,rp=struct.unpack_from("<IIII",x86,o+8); break
text=x86[rp:rp+rs]
def find_callers(target_rva):
    res=[]
    for i in range(len(text)-5):
        if text[i]==0xE8:
            rel=struct.unpack_from("<i",text,i+1)[0]
            if va+i+5+rel==target_rva: res.append(va+i)
    return res
for t in (0x70cf, 0xcdc6):
    cs=find_callers(t)
    print(f"callers of {t:#x}:", [hex(c) for c in cs])
# dump context of callers of 70cf
for c in find_callers(0x70cf):
    print(f"\n==== around caller {c:#x} ====")
    off=rp+(c-0x60-va)
    for insn in md.disasm(x86[off:off+0x80], ib+c-0x60):
        mark="<<" if insn.address==ib+c else "  "
        print(f"{mark}{insn.address:#x}: {insn.mnemonic} {insn.op_str}")
