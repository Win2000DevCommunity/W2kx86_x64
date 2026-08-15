import pathlib, struct, shutil, subprocess, os
src=pathlib.Path("build_univ230/cmd_fix23.exe")
dst=pathlib.Path("build_univ230/cmd_fix24.exe")
shutil.copy2(src,dst)
pe=bytearray(dst.read_bytes())
e=struct.unpack_from("<I",pe,0x3C)[0]
ns=struct.unpack_from("<H",pe,e+6)[0]; so=struct.unpack_from("<H",pe,e+20)[0]; sec=e+24+so
for i in range(ns):
    o=sec+i*40
    if pe[o:o+5]==b".text":
        vs,va,rs,rp=struct.unpack_from("<IIII",pe,o+8); break
def ro(r): return rp+(r-va)
for site,opc in ((0x27262+3,"0f84"),(0x27275+3,"0f85")):
    pass
# je 0x27239 @0x27265 -> 0x272a2 ; jne 0x27239 @0x27278 -> 0x272a2
for site in (0x27265, 0x27278):
    o=ro(site)
    assert pe[o]==0x0F and pe[o+1] in (0x84,0x85), bytes(pe[o:o+6]).hex()
    old=site+6+struct.unpack_from("<i",pe,o+2)[0]
    struct.pack_into("<i",pe,o+2, 0x272a2-(site+6))
    print(f"  {site:#x}: target {old:#x} -> 0x272a2")
dst.write_bytes(pe)
os.chdir("build_univ230")
r=subprocess.run(["cmd_fix24.exe","/c","echo","w2ktest"],capture_output=True,timeout=25)
print("rc", hex(r.returncode&0xffffffff))
out=r.stdout.decode("utf-8","replace")
print(out[:1200])
print("HAS w2ktest:", "w2ktest" in out)
