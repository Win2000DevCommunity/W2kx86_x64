import struct, shutil
from pathlib import Path
from tools.audit_calls import read_text_section, load_map
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

src=Path("build_univ7/cmd_pure.exe")
dst=Path("build_univ7_patch/cmd_pure.exe")
dst.parent.mkdir(exist_ok=True)
shutil.copy(src,dst)
shim=src.with_name("w2kshim64.dll")
if shim.exists(): shutil.copy(shim, dst.with_name("w2kshim64.dll"))
blob=bytearray(dst.read_bytes())
e=struct.unpack_from("<I",blob,0x3c)[0]
num=struct.unpack_from("<H",blob,e+6)[0]; soh=struct.unpack_from("<H",blob,e+20)[0]; sec=e+24+soh
for i in range(num):
    o=sec+i*40
    if blob[o:o+5]==b".text":
        vs,va,rs,rp=struct.unpack_from("<IIII",blob,o+8); trva,traw,tsz=va,rp,rs; break
data=memoryview(blob)[traw:traw+tsz]
# find cmp rcx,0 after pops near old map
real=None
for i in range(len(data)-4):
    if bytes(data[i:i+4])==bytes.fromhex("4883f900"):
        # prefer one preceded by nops/ret from epilogue
        if i>=4 and data[i-1] in (0x90,0xc3,0xcc):
            real=trva+i
            if real>=0x2f000: break
print("using", hex(real))
# patch calls from the 0x49a18 function that currently hit XcptFilter thunk
# XcptFilter iat 0x8a5d0 - find thunks with that imm
iat=bytes.fromhex("d0a5088000000000")
fixed=0
for i in range(len(data)-20):
    if data[i]!=0xe8: continue
    if bytes(data[i-4:i])!=bytes.fromhex("4883e4f0"): continue
    t=(trva+i+5+struct.unpack_from("<i",data,i+1)[0])&0xffffffff
    to=t-trva
    # is thin iat thunk to 0x8a5d0?
    body=to
    if bytes(data[to:to+2])==b"\x41\x55":
        body=to+13
    if body+10<=len(data) and bytes(data[body:body+2])==b"\x48\xb8" and bytes(data[body+2:body+10])==iat:
        # only patch if caller is in 0x49a00..0x4b000 (the switch parser region)
        if 0x49000 <= trva+i <= 0x4b000:
            struct.pack_into("<i", blob, traw+i+1, real-(trva+i+5))
            fixed+=1
print("patched", fixed)
dst.write_bytes(blob)
