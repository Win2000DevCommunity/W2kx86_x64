import pathlib, struct, shutil, subprocess, os
src=pathlib.Path("build_univ230/cmd_fix20.exe")
dst=pathlib.Path("build_univ230/cmd_fix21.exe")
shutil.copy2(src,dst)
pe=bytearray(dst.read_bytes())
e=struct.unpack_from("<I",pe,0x3C)[0]
ns=struct.unpack_from("<H",pe,e+6)[0]; so=struct.unpack_from("<H",pe,e+20)[0]; sec=e+24+so
for i in range(ns):
    o=sec+i*40
    if pe[o:o+5]==b".text":
        vs,va,rs,rp=struct.unpack_from("<IIII",pe,o+8); break
T0,T1=rp,rp+rs
def ro(rva): return rp+(rva-va)
print("18f7f:", bytes(pe[ro(0x18f7f):ro(0x18f7f)+10]).hex())
print("18fa8:", bytes(pe[ro(0x18fa8):ro(0x18fa8)+10]).hex())

cur=[T0]
def cave(need):
    run=0; i=cur[0]
    while i<T1:
        if pe[i] in (0x00,0xCC):
            run+=1
            if run>=need+2:
                st=i-run+2; cur[0]=st+need; return st
        else: run=0
        i+=1
    return -1

def detour(rva, broken_len, fixed):
    site=ro(rva)
    c=cave(len(fixed)+5)
    assert c>=0
    body=bytearray(fixed)
    back=site+broken_len
    body+=bytes([0xE9])+struct.pack("<i", back-(c+len(body)+5))
    pe[c:c+len(body)]=body
    pe[site:site+broken_len]=(bytes([0xE9])+struct.pack("<i", c-(site+5))
                              + b"\x90"*(broken_len-5))
    print(f"  detour {rva:#x} len={broken_len} -> cave {va+c-rp:#x}")

# mov word [rbp+rbx*2-0x210], si
detour(0x18f7f, 7, bytes.fromhex("6689b45df0fdffff"))
# and word [rbp+rbx*2-0x210], 0
detour(0x18fa8, 8, bytes.fromhex("6683a45df0fdffff00"))

dst.write_bytes(pe)
os.chdir("build_univ230")
r=subprocess.run(["cmd_fix21.exe","/c","echo","w2ktest"],capture_output=True,timeout=25)
print("rc", hex(r.returncode&0xffffffff))
out=r.stdout.decode("utf-8","replace")
print(out[:1500])
print("HAS w2ktest:", "w2ktest" in out)
