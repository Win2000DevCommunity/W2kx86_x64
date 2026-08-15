import pathlib, struct, shutil, subprocess, os
from keystone import Ks, KS_ARCH_X86, KS_MODE_64
ks=Ks(KS_ARCH_X86, KS_MODE_64)

src=pathlib.Path("build_univ230/cmd_fix5.exe")
dst=pathlib.Path("build_univ230/cmd_fix6.exe")
shutil.copy2(src, dst)
pe=bytearray(dst.read_bytes())
e=struct.unpack_from("<I",pe,0x3C)[0]
ns=struct.unpack_from("<H",pe,e+6)[0]; so=struct.unpack_from("<H",pe,e+20)[0]; sec=e+24+so
for i in range(ns):
    o=sec+i*40
    if pe[o:o+5]==b".text":
        vs,va,rs,rp=struct.unpack_from("<IIII",pe,o+8); break

def rva_off(rva):
    return rp+(rva-va)

# half-fix at d9bc: B8 01 00 00 00 90 90 5E C9 C3
off=rva_off(0xd9bc)
cur=bytes(pe[off:off+10])
print("before", cur.hex())
# also scan whole text for half-fix and broken forms
fixed=0
for imm in (1,2,5,0,3,4):
    imm4=struct.pack("<I",imm)
    repl=bytes([0xB8])+imm4+bytes([0x5F,0x5E,0x5B,0xC9,0xC3])
    for pat in (
        bytes([0x48,0xc7,0xc6])+imm4+bytes([0x5E,0xC9,0xC3]),
        bytes([0xB8])+imm4+bytes([0x90,0x90,0x5E,0xC9,0xC3]),
    ):
        i=rp
        end=rp+rs
        while True:
            j=pe.find(pat, i, end)
            if j<0: break
            pe[j:j+10]=repl
            fixed+=1
            print(f"  patch @text+{j-rp:#x} imm={imm}")
            i=j+10
print("fixed", fixed)
print("after d9bc", bytes(pe[off:off+10]).hex())
dst.write_bytes(pe)

os.chdir("build_univ230")
r=subprocess.run(["cmd_fix6.exe","/c","echo","w2ktest"], capture_output=True, timeout=20)
print("rc", r.returncode)
print("out", r.stdout.decode("utf-8","replace")[:500])
print("err", r.stderr.decode("utf-8","replace")[:300])
