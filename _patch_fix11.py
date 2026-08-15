import pathlib, struct, shutil, subprocess, os
src=pathlib.Path("build_univ230/cmd_fix10.exe")
dst=pathlib.Path("build_univ230/cmd_fix11.exe")
shutil.copy2(src, dst)
pe=bytearray(dst.read_bytes())
e=struct.unpack_from("<I",pe,0x3C)[0]
ns=struct.unpack_from("<H",pe,e+6)[0]; so=struct.unpack_from("<H",pe,e+20)[0]; sec=e+24+so
for i in range(ns):
    o=sec+i*40
    if pe[o:o+5]==b".text":
        vs,va,rs,rp=struct.unpack_from("<IIII",pe,o+8); break
epi=bytes.fromhex("4889e85f5e5d5bc3"); home=bytes.fromhex("48894c2408")
n=0; i=rp; end=rp+rs
while i < end-5:
    if pe[i]==0xE8:
        rel=struct.unpack_from("<i",pe,i+1)[0]; tgt=i+5+rel
        if rp<=tgt<=end-13 and pe[tgt:tgt+8]==epi and pe[tgt+8:tgt+13]==home:
            struct.pack_into("<i",pe,i+1,(tgt+8)-(i+5)); n+=1
            print(f"  retarget call @ {va+i-rp:#x} -> {va+tgt-rp+8:#x}")
        i+=5
    else:
        i+=1
print("fixed", n)
dst.write_bytes(pe)
os.chdir("build_univ230")
r=subprocess.run(["cmd_fix11.exe","/c","echo","w2ktest"], capture_output=True, timeout=20)
print("rc", r.returncode, hex(r.returncode & 0xffffffff))
out=r.stdout.decode("utf-8","replace")
print(out[:1200])
print("has w2ktest", "w2ktest" in out)
