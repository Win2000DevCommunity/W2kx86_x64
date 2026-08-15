import pathlib, struct, shutil, subprocess, os
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
md=Cs(CS_ARCH_X86, CS_MODE_64)

src=pathlib.Path("build_univ230/cmd_fix13.exe")
dst=pathlib.Path("build_univ230/cmd_fix20.exe")
shutil.copy2(src,dst)
pe=bytearray(dst.read_bytes())
e=struct.unpack_from("<I",pe,0x3C)[0]
ns=struct.unpack_from("<H",pe,e+6)[0]; so=struct.unpack_from("<H",pe,e+20)[0]; sec=e+24+so
for i in range(ns):
    o=sec+i*40
    if pe[o:o+5]==b".text":
        vs,va,rs,rp=struct.unpack_from("<IIII",pe,o+8); break
T0,T1=rp,rp+rs

cave_cursor=[T0]
def find_cave(need):
    run=0; i=cave_cursor[0]
    while i < T1:
        if pe[i] in (0x00,0xCC):
            run+=1
            if run>=need+2:
                start=i-run+2
                cave_cursor[0]=start+need
                return start
        else:
            run=0
        i+=1
    return -1

sig=bytes([0x4C,0x89,0xEC,0x41,0x5D,0x48,0x89,0xC1])
stub_head=bytes([0x41,0x55,0x49,0x89,0xE5])
stub_tail=bytes([0x48,0x83,0xEC])
rax_args={
 bytes([0x49,0x89,0xC0]):bytes([0x41,0x58,0x90]),
 bytes([0x49,0x89,0xC1]):bytes([0x41,0x59,0x90]),
 bytes([0x48,0x89,0xC2]):bytes([0x5A,0x90,0x90]),
}
fixed=0; i=T0
while True:
    at=pe.find(sig,i,T1)
    if at<0: break
    i=at+1
    stub=pe.rfind(stub_head,max(T0,at-0x60),at)
    if stub<0 or pe[stub+5:stub+8]!=stub_tail: continue
    span=bytes(pe[stub+8:at])
    n_call=(span.count(bytes([0xFF,0xD0]))+span.count(bytes([0x41,0xFF,0xD7]))
            +span.count(bytes([0x41,0xFF,0xD6]))+span.count(bytes([0x41,0xFF,0xD5]))
            +span.count(bytes([0xFF,0xD3]))+span.count(bytes([0xE8])))
    if n_call!=1: continue
    p=at+len(sig); hit=-1; key=b""
    while p < min(T1, at+len(sig)+0x20):
        three=bytes(pe[p:p+3])
        if three in rax_args:
            if hit>=0:
                hit=-1; break
            hit=p; key=three; p+=3; continue
        if pe[p:p+3]==bytes([0x48,0xC7,0xC2]):
            p+=7; continue
        if three[:2] in (bytes([0x49,0x89]),bytes([0x48,0x89])):
            p+=3; continue
        break
    if hit<0: continue
    cave=find_cave(12)
    if cave<0: continue
    body=bytearray(); body+=bytes([0x50]); body+=stub_head
    back=stub+5
    body+=bytes([0xE9])+struct.pack("<i", back-(cave+len(body)+5))
    pe[cave:cave+len(body)]=body
    pe[stub:stub+5]=bytes([0xE9])+struct.pack("<i", cave-(stub+5))
    pe[hit:hit+3]=rax_args[key]
    fixed+=1
    print(f"  rax-arg save @ stub {va+stub-rp:#x} arg {va+hit-rp:#x} cave {va+cave-rp:#x}")
print("RAX-arg heals:", fixed)

# hand fixes still needing universal treatment
off=rp+(0x28b88-va)
assert pe[off]==0x0F and pe[off+1]==0x84
struct.pack_into("<i",pe,off+2,(rp+(0x28bd0-va))-(off+6)); print("je 28b88 -> 28bd0")
off=rp+(0xc622-va)
assert pe[off]==0xE8
struct.pack_into("<i",pe,off+1,(rp+(0xc940-va))-(off+5)); print("call c622 -> c940")
off=rp+(0xc954-va)
if pe[off:off+2]==bytes.fromhex("6aff"):
    pe[off:off+43]=bytes.fromhex("4883ec20")+b"\x90"*39; print("SEH nop c954")

dst.write_bytes(pe)
os.chdir("build_univ230")
r=subprocess.run(["cmd_fix20.exe","/c","echo","w2ktest"],capture_output=True,timeout=25)
print("rc", hex(r.returncode&0xffffffff))
out=r.stdout.decode("utf-8","replace")
print(out[:1500])
print("HAS", "w2ktest" in out)
