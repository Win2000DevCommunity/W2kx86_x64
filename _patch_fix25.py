import pathlib, struct, shutil, subprocess, os
src=pathlib.Path("build_univ230/cmd_fix23.exe")
dst=pathlib.Path("build_univ230/cmd_fix25.exe")
shutil.copy2(src,dst)
pe=bytearray(dst.read_bytes())
e=struct.unpack_from("<I",pe,0x3C)[0]
ns=struct.unpack_from("<H",pe,e+6)[0]; so=struct.unpack_from("<H",pe,e+20)[0]; sec=e+24+so
for i in range(ns):
    o=sec+i*40
    if pe[o:o+5]==b".text":
        vs,va,rs,rp=struct.unpack_from("<IIII",pe,o+8); break
T0,T1=rp,rp+rs
def ro(r): return rp+(r-va)
def cave(need):
    run=0; i=T0
    while i<T1:
        if pe[i] in (0x00,0xCC):
            run+=1
            if run>=need+2: return i-run+2
        else: run=0
        i+=1
    return -1
EPI=0x2729f   # pop rdi; pop rsi; ret
body=bytearray()
body+=bytes.fromhex("488b4c2428")        # mov rcx,[rsp+0x28]  (arg3 = out ptr)
body+=bytes.fromhex("8d047f")            # lea eax,[rdi+rdi*2]
body+=bytes.fromhex("49bb")+struct.pack("<Q",0x800588e8)
body+=bytes.fromhex("66418b04c3")        # mov ax, word [r11+rax*8]
body+=bytes.fromhex("668901")            # mov word [rcx], ax
body+=bytes.fromhex("49bb")+struct.pack("<Q",0x800587d8)
body+=bytes.fromhex("41893b")            # mov [r11], edi
body+=bytes.fromhex("89f8")              # mov eax, edi
c=cave(len(body)+5); assert c>=0
crva=va+c-rp
body+=bytes([0xE9])+struct.pack("<i", ro(EPI)-(c+len(body)+5))
pe[c:c+len(body)]=body
print(f"  materialized match block at {crva:#x} ({len(body)} bytes)")
for site in (0x27265, 0x27278):
    o=ro(site)
    assert pe[o]==0x0F and pe[o+1] in (0x84,0x85)
    struct.pack_into("<i",pe,o+2, crva-(site+6))
    print(f"  {site:#x} -> {crva:#x}")
dst.write_bytes(pe)
os.chdir("build_univ230")
r=subprocess.run(["cmd_fix25.exe","/c","echo","w2ktest"],capture_output=True,timeout=25)
print("rc", hex(r.returncode&0xffffffff))
out=r.stdout.decode("utf-8","replace")
print(out[:1200])
print("HAS w2ktest:", "w2ktest" in out)
