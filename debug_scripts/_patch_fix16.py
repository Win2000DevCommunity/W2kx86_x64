import pathlib, struct, shutil, subprocess, os

src=pathlib.Path("build_univ230/cmd_fix15.exe")
dst=pathlib.Path("build_univ230/cmd_fix16.exe")
shutil.copy2(src, dst)
pe=bytearray(dst.read_bytes())
e=struct.unpack_from("<I",pe,0x3C)[0]
ns=struct.unpack_from("<H",pe,e+6)[0]; so=struct.unpack_from("<H",pe,e+20)[0]; sec=e+24+so
for i in range(ns):
    o=sec+i*40
    if pe[o:o+5]==b".text":
        vs,va,rs,rp=struct.unpack_from("<IIII",pe,o+8); break

def retarget(call_rva, new_tgt):
    off=rp+(call_rva-va)
    assert pe[off]==0xE8
    old=off+5+struct.unpack_from("<i",pe,off+1)[0]
    struct.pack_into("<i", pe, off+1, (rp+(new_tgt-va))-(off+5))
    print(f"call @{call_rva:#x}: {va+old-rp:#x} -> {new_tgt:#x}")

# find all calls to 19dc4 that have the 7-arg stack setup pattern before them
# specifically c622
retarget(0xc622, 0xc940)

# also check if other calls to 19dc4 should be print - scan for same stack setup
i=rp
end=rp+rs
tgt_alloc=rp+(0x19dc4-va)
count=0
while i < end-5:
    if pe[i]==0xE8:
        rel=struct.unpack_from("<i",pe,i+1)[0]
        if i+5+rel == tgt_alloc:
            rva=va+i-rp
            # look for mov [rsp+0x30] shortly before
            window=pe[max(rp,i-0x30):i]
            if bytes.fromhex("4889442430") in window or bytes.fromhex("48897c2430") in window:
                print(f"  candidate 7arg call to alloc @{rva:#x}")
            count+=1
        i+=5
    else:
        i+=1
print("total calls to 19dc4", count)

dst.write_bytes(pe)
os.chdir("build_univ230")
r=subprocess.run(["cmd_fix16.exe","/c","echo","w2ktest"], capture_output=True, timeout=20)
print("rc", hex(r.returncode&0xffffffff))
out=r.stdout.decode("utf-8","replace")
print(out[:2000])
print("has w2ktest", "w2ktest" in out)
