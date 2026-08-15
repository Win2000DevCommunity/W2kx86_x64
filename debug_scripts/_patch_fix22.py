import pathlib, struct, shutil, subprocess, os
src=pathlib.Path("build_univ230/cmd_fix21.exe")
dst=pathlib.Path("build_univ230/cmd_fix22.exe")
shutil.copy2(src,dst)
pe=bytearray(dst.read_bytes())
e=struct.unpack_from("<I",pe,0x3C)[0]
ns=struct.unpack_from("<H",pe,e+6)[0]; so=struct.unpack_from("<H",pe,e+20)[0]; sec=e+24+so
for i in range(ns):
    o=sec+i*40
    if pe[o:o+5]==b".text":
        vs,va,rs,rp=struct.unpack_from("<IIII",pe,o+8); break
def ro(r): return rp+(r-va)
def put(rva, old, new):
    o=ro(rva); cur=bytes(pe[o:o+len(old)//2])
    assert cur==bytes.fromhex(old), f"{rva:#x} has {cur.hex()} want {old}"
    assert len(new)==len(old)
    pe[o:o+len(old)//2]=bytes.fromhex(new)
    print(f"  patched {rva:#x}: {old} -> {new}")
# (A) push dword [esi-8] lost: xor rdx,rdx -> mov edx, dword [rsi-8]
put(0x27236, "4831d2", "8b56f8")
# (B) esp-relative arg1 reads -> Win64 home slot ([rsp+8] + 2 saved regs)
put(0x2721d, "397c240c", "397c2418")
put(0x27285, "3b7c240c", "3b7c2418")
dst.write_bytes(pe)
os.chdir("build_univ230")
r=subprocess.run(["cmd_fix22.exe","/c","echo","w2ktest"],capture_output=True,timeout=25)
print("rc", hex(r.returncode&0xffffffff))
out=r.stdout.decode("utf-8","replace")
print(out[:1200])
print("HAS w2ktest:", "w2ktest" in out)
