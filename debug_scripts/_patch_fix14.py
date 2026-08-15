import pathlib, struct, shutil, subprocess, os
from keystone import Ks, KS_ARCH_X86, KS_MODE_64
ks=Ks(KS_ARCH_X86, KS_MODE_64)

src=pathlib.Path("build_univ230/cmd_fix13.exe")
dst=pathlib.Path("build_univ230/cmd_fix14.exe")
shutil.copy2(src, dst)
pe=bytearray(dst.read_bytes())
e=struct.unpack_from("<I",pe,0x3C)[0]
ns=struct.unpack_from("<H",pe,e+6)[0]; so=struct.unpack_from("<H",pe,e+20)[0]; sec=e+24+so
for i in range(ns):
    o=sec+i*40
    if pe[o:o+5]==b".text":
        vs,va,rs,rp=struct.unpack_from("<IIII",pe,o+8); break

# pattern from lea through mov r9,rax
pat=bytes.fromhex(
 "488d440014"  # lea rax,[rax+rax+0x14]
 "41554989e54883ec204883e4f041ffd74c89ec415d"  # align call r15
 "4889c1"  # mov rcx,rax
 "48c7c200000000"  # mov rdx,0
 "4989d8"  # mov r8,rbx
 "4989c1"  # mov r9,rax
)
print("pat len", len(pat), "found", pe.find(pat, rp, rp+rs))

repl=bytes.fromhex(
 "488d440014"  # lea
 "4989c1"  # mov r9,rax  SAVE SIZE
 "41554989e54883ec204883e4f041ffd74c89ec415d"  # call GetProcessHeap
 "4889c1"  # mov rcx,rax
 "31d2"  # xor edx,edx
 "4989d8"  # mov r8,rbx
 "90909090"  # nops (pad to same length)
)
# check lengths
print("repl len", len(repl))
# adjust padding
while len(repl) < len(pat):
    repl += b"\x90"
assert len(repl)==len(pat)

off=pe.find(pat, rp, rp+rs)
assert off>=0
pe[off:off+len(pat)]=repl
print("patched at", hex(va+off-rp))
dst.write_bytes(pe)

os.chdir("build_univ230")
r=subprocess.run(["cmd_fix14.exe","/c","echo","w2ktest"], capture_output=True, timeout=20)
print("rc", hex(r.returncode&0xffffffff))
out=r.stdout.decode("utf-8","replace")
print(out[:1500])
print("has w2ktest", "w2ktest" in out)
