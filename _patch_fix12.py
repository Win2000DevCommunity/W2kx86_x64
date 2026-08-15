import pathlib, struct, shutil, subprocess, os, sys, ctypes as C
sys.path.insert(0,".")
import dbg_fault as df

# Apply all three heals on fix5 base with refined add-rsp
src=pathlib.Path("build_univ230/cmd_fix5.exe")
dst=pathlib.Path("build_univ230/cmd_fix12.exe")
shutil.copy2(src, dst)
pe=bytearray(dst.read_bytes())
e=struct.unpack_from("<I",pe,0x3C)[0]
ns=struct.unpack_from("<H",pe,e+6)[0]; so=struct.unpack_from("<H",pe,e+20)[0]; sec=e+24+so
for i in range(ns):
    o=sec+i*40
    if pe[o:o+5]==b".text":
        vs,va,rs,rp=struct.unpack_from("<IIII",pe,o+8); break
text_end=rp+rs

def has_pre(stub_push):
    start=max(rp, stub_push-12); k=start
    while k < stub_push:
        b=pe[k]
        if 0x50<=b<=0x57: return True
        if b==0x6A and k+1<stub_push: return True
        if b==0x68 and k+4<stub_push: return True
        if b==0x41 and k+1<stub_push and 0x50<=pe[k+1]<=0x57:
            if pe[k+1]==0x55 and k+2==stub_push: break
            return True
        if b in (0x48,0x49) and k+1<stub_push and 0x50<=pe[k+1]<=0x57: return True
        k+=1
    return False

# pushimm
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
            j=pe.find(pat,i,text_end)
            if j<0: break
            window=pe[j:j+0x600]
            if epi3 in window: repl=bytes([0xB8])+imm4+bytes([0x5F,0x5E,0x5B,0xC9,0xC3])
            elif epi2 in window: repl=bytes([0xB8])+imm4+bytes([0x5F,0x5E,0x90,0xC9,0xC3])
            else: repl=bytes([0xB8])+imm4+bytes([0x90,0x90,0x5E,0xC9,0xC3])
            pe[j:j+10]=repl; n_pr+=1; i=j+10

# refined add-rsp
n_asr=0
for prefix in (bytes.fromhex("4c89ec415d"), bytes.fromhex("498be5415d")):
    i=rp
    while True:
        j=pe.find(prefix,i,text_end)
        if j<0: break
        stub_push=pe.rfind(bytes([0x41,0x55]), max(rp,j-0x20), j)
        k=j+5
        if stub_push>=0 and has_pre(stub_push):
            i=j+1; continue
        if k+3<text_end and pe[k:k+3]==bytes([0x48,0x83,0xC4]) and pe[k+3]!=0:
            pe[k:k+4]=b"\x90"*4; n_asr+=1; i=k+4; continue
        if k+6<text_end and pe[k:k+3]==bytes([0x48,0x81,0xC4]):
            imm=struct.unpack_from("<I",pe,k+3)[0]
            if 0<imm<=0x100:
                pe[k:k+7]=b"\x90"*7; n_asr+=1; i=k+7; continue
        i=j+1

# epi call retarget
epi=bytes.fromhex("4889e85f5e5d5bc3"); home=bytes.fromhex("48894c2408")
n_cep=0; i=rp
while i < text_end-5:
    if pe[i]==0xE8:
        rel=struct.unpack_from("<i",pe,i+1)[0]; tgt=i+5+rel
        if rp<=tgt<=text_end-13 and pe[tgt:tgt+8]==epi and pe[tgt+8:tgt+13]==home:
            struct.pack_into("<i",pe,i+1,(tgt+8)-(i+5)); n_cep+=1
        i+=5
    else:
        i+=1
print("pushimm",n_pr,"addrsp",n_asr,"cep",n_cep)
dst.write_bytes(pe)

os.chdir("build_univ230")
r=subprocess.run(["cmd_fix12.exe","/c","echo","w2ktest"], capture_output=True, timeout=20)
print("rc", r.returncode, hex(r.returncode&0xffffffff))
out=r.stdout.decode("utf-8","replace")
print(out[:1200])
print("has w2ktest", "w2ktest" in out)
