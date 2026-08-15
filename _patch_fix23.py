import pathlib, struct, shutil, subprocess, os
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
md=Cs(CS_ARCH_X86, CS_MODE_64)
src=pathlib.Path("build_univ230/cmd_fix22.exe")
dst=pathlib.Path("build_univ230/cmd_fix23.exe")
shutil.copy2(src,dst)
pe=bytearray(dst.read_bytes())
e=struct.unpack_from("<I",pe,0x3C)[0]
ns=struct.unpack_from("<H",pe,e+6)[0]; so=struct.unpack_from("<H",pe,e+20)[0]; sec=e+24+so
for i in range(ns):
    o=sec+i*40
    if pe[o:o+5]==b".text":
        vs,va,rs,rp=struct.unpack_from("<IIII",pe,o+8); break
# Any code constant pointing at 0x80047ce4 (bogus embedded copy) -> real table 0x800588e8
bad=struct.pack("<Q", 0x80047ce4); good=struct.pack("<Q", 0x800588e8)
n=0; i=rp
while True:
    j=pe.find(bad, i, rp+rs)
    if j<0: break
    pe[j:j+8]=good; n+=1
    print(f"  fixed qword imm @ rva {va+j-rp:#x}")
    i=j+8
bad4=struct.pack("<I", 0x80047ce4); good4=struct.pack("<I", 0x800588e8)
i=rp
while True:
    j=pe.find(bad4, i, rp+rs)
    if j<0: break
    pe[j:j+4]=good4; n+=1
    print(f"  fixed dword imm @ rva {va+j-rp:#x}")
    i=j+4
print("constants fixed:", n)
dst.write_bytes(pe)
os.chdir("build_univ230")
r=subprocess.run(["cmd_fix23.exe","/c","echo","w2ktest"],capture_output=True,timeout=25)
print("rc", hex(r.returncode&0xffffffff))
out=r.stdout.decode("utf-8","replace")
print(out[:1200])
print("HAS w2ktest:", "w2ktest" in out)
