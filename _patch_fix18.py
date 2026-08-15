import pathlib, struct, shutil, subprocess, os, sys, ctypes as C
sys.path.insert(0,".")
import dbg_fault as df

src=pathlib.Path("build_univ230/cmd_fix17.exe")
dst=pathlib.Path("build_univ230/cmd_fix18.exe")
shutil.copy2(src, dst)
pe=bytearray(dst.read_bytes())
e=struct.unpack_from("<I",pe,0x3C)[0]
ns=struct.unpack_from("<H",pe,e+6)[0]; so=struct.unpack_from("<H",pe,e+20)[0]; sec=e+24+so
for i in range(ns):
    o=sec+i*40
    if pe[o:o+5]==b".text":
        vs,va,rs,rp=struct.unpack_from("<IIII",pe,o+8); break

pat=bytes.fromhex(
 "488d440820"
 "41554989e54883ec204883e4f0"
 "48b8e043088000000000"
 "488b00ffd0"
 "4c89ec415d"
 "4889c1"
 "48c7c208000000"
 "4989c0"
)
print("pat", len(pat), "at", pe.find(pat,rp,rp+rs))
repl=bytes.fromhex(
 "488d440820"  # lea
 "4989c0"  # mov r8,rax SAVE SIZE
 "41554989e54883ec204883e4f0"
 "48b8e043088000000000"
 "488b00ffd0"
 "4c89ec415d"
 "4889c1"  # mov rcx,rax
 "6a085a"  # push 8; pop rdx
 "909090"  # nops (was mov r8,rax)
)
print("repl", len(repl))
while len(repl)<len(pat): repl+=b"\x90"
assert len(repl)==len(pat)
off=pe.find(pat,rp,rp+rs)
pe[off:off+len(pat)]=repl
print("patched", hex(va+off-rp))
dst.write_bytes(pe)

os.chdir("build_univ230")
r=subprocess.run(["cmd_fix18.exe","/c","echo","w2ktest"], capture_output=True, timeout=20)
print("rc", hex(r.returncode&0xffffffff))
out=r.stdout.decode("utf-8","replace")
print(out[:2000])
print("HAS", "w2ktest" in out)
