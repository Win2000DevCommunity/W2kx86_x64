import pathlib, struct, shutil, subprocess, os, sys, ctypes as C
sys.path.insert(0,".")
import dbg_fault as df

# apply heals on fix5 base
src=pathlib.Path("build_univ230/cmd_fix5.exe")
dst=pathlib.Path("build_univ230/cmd_fix9.exe")
shutil.copy2(src, dst)
pe=bytearray(dst.read_bytes())
e=struct.unpack_from("<I",pe,0x3C)[0]
ns=struct.unpack_from("<H",pe,e+6)[0]; so=struct.unpack_from("<H",pe,e+20)[0]; sec=e+24+so
for i in range(ns):
    o=sec+i*40
    if pe[o:o+5]==b".text":
        vs,va,rs,rp=struct.unpack_from("<IIII",pe,o+8); break

# 1) push-imm returns with epi-aware pops
epi3=bytes([0x5F,0x5E,0x5B,0xC9,0xC3]); epi2=bytes([0x5F,0x5E,0xC9,0xC3])
n_pr=0
for imm in (1,2,5,0,3,4):
    imm4=struct.pack("<I",imm)
    for pat in (
        bytes([0x48,0xc7,0xc6])+imm4+bytes([0x5E,0xC9,0xC3]),
        bytes([0xB8])+imm4+bytes([0x90,0x90,0x5E,0xC9,0xC3]),
    ):
        i=rp
        while True:
            j=pe.find(pat,i,rp+rs)
            if j<0: break
            window=pe[j:j+0x600]
            if epi3 in window:
                repl=bytes([0xB8])+imm4+bytes([0x5F,0x5E,0x5B,0xC9,0xC3])
            elif epi2 in window:
                repl=bytes([0xB8])+imm4+bytes([0x5F,0x5E,0x90,0xC9,0xC3])
            else:
                repl=bytes([0xB8])+imm4+bytes([0x90,0x90,0x5E,0xC9,0xC3])
            pe[j:j+10]=repl; n_pr+=1; i=j+10
print("pushimm", n_pr)

# 2) nop spurious add rsp after align
prefix=bytes([0x49,0x8B,0xE5,0x41,0x5D])
n_asr=0; i=rp
while True:
    j=pe.find(prefix,i,rp+rs)
    if j<0: break
    k=j+5
    if k+3<rp+rs and pe[k:k+3]==bytes([0x48,0x83,0xC4]) and pe[k+3]!=0:
        pe[k:k+4]=b"\x90"*4; n_asr+=1; i=k+4; continue
    if k+6<rp+rs and pe[k:k+3]==bytes([0x48,0x81,0xC4]):
        imm=struct.unpack_from("<I",pe,k+3)[0]
        if 0<imm<=0x100:
            pe[k:k+7]=b"\x90"*7; n_asr+=1; i=k+7; continue
    if k+2<rp+rs and pe[k]==0x83 and pe[k+1]==0xC4 and pe[k+2]!=0:
        pe[k:k+3]=b"\x90"*3; n_asr+=1; i=k+3; continue
    i=j+1
print("addrsp nops", n_asr)
dst.write_bytes(pe)

os.chdir("build_univ230")
r=subprocess.run(["cmd_fix9.exe","/c","echo","w2ktest"], capture_output=True, timeout=20)
print("rc", r.returncode, hex(r.returncode & 0xffffffff))
out=r.stdout.decode("utf-8","replace")
print("out", out[:800])
print("has w2ktest", "w2ktest" in out)
