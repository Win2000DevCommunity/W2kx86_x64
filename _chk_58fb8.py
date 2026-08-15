from capstone import Cs, CS_ARCH_X86, CS_MODE_64
import struct, pathlib
pe=bytearray(pathlib.Path("build_univ230/cmd_fix2.exe").read_bytes())
e=struct.unpack_from("<I",pe,0x3C)[0]
ns=struct.unpack_from("<H",pe,e+6)[0]; so=struct.unpack_from("<H",pe,e+20)[0]; sec=e+24+so
ib=struct.unpack_from("<Q",pe,e+24+24)[0]
for i in range(ns):
    o=sec+i*40
    if pe[o:o+5]==b".text":
        vs,va,rs,rp=struct.unpack_from("<IIII",pe,o+8); break
code=bytes(pe[rp:rp+rs]); md=Cs(CS_ARCH_X86,CS_MODE_64)
# find refs to 58fb8
target=struct.pack("<Q", 0x80058fb8)
count=0
for i in range(len(code)-10):
    if code[i:i+2] in (b'\x49\xbb', b'\x48\xb8', b'\x48\xb9', b'\x4c\xbb') and code[i+2:i+10]==target:
        for insn in md.disasm(code[i:i+20], ib+va+i):
            print(f"{insn.address:#x}: {insn.mnemonic} {insn.op_str}")
            break
        # next few
        for insn in list(md.disasm(code[i:i+24], ib+va+i))[:4]:
            print(f"  {insn.address:#x}: {insn.mnemonic} {insn.op_str}")
        print("---")
        count+=1
        if count>12: break
print("total shown", count)
# build status
import pathlib
print("univ231", pathlib.Path("../build_univ231/cmd_pure.exe").exists() if False else pathlib.Path("build_univ231/cmd_pure.exe").exists())
