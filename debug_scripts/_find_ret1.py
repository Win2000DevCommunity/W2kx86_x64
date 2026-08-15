from capstone import Cs, CS_ARCH_X86, CS_MODE_64
import struct, pathlib
pe=bytearray(pathlib.Path("build_univ230/cmd_fix3.exe").read_bytes())
e=struct.unpack_from("<I",pe,0x3C)[0]
ns=struct.unpack_from("<H",pe,e+6)[0]; so=struct.unpack_from("<H",pe,e+20)[0]; sec=e+24+so
ib=struct.unpack_from("<Q",pe,e+24+24)[0]
for i in range(ns):
    o=sec+i*40
    if pe[o:o+5]==b".text":
        vs,va,rs,rp=struct.unpack_from("<IIII",pe,o+8); break
code=bytearray(pe[rp:rp+rs]); md=Cs(CS_ARCH_X86,CS_MODE_64)
# find b8 01 00 00 00 or c7 c0 01 in d08c..deb1
start,end=0xd08c-va,0xdeb1-va
for i in range(start, end):
    if code[i:i+5]==bytes([0xb8,1,0,0,0]):
        print(f"mov eax,1 at {ib+va+i:#x}")
    if code[i:i+7]==bytes([0x48,0xc7,0xc0,1,0,0,0]):
        print(f"mov rax,1 at {ib+va+i:#x}")
    if code[i:i+5]==bytes([0xb8,2,0,0,0]):
        print(f"mov eax,2 at {ib+va+i:#x}")
# push 1; pop rax patterns? 
# look for jmp to shared that pops return code
# BP at deb1 and d9c5
