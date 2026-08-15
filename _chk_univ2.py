# Patch mid-insn + bare epi already applied; add mid snap to univ exe
import struct, pathlib, subprocess, sys
sys.path.insert(0, ".")
import dbg_fault as df

pe = bytearray(pathlib.Path("build_univ227/cmd_univ.exe").read_bytes())
e = struct.unpack_from("<I", pe, 0x3C)[0]
ns = struct.unpack_from("<H", pe, e+6)[0]
so = struct.unpack_from("<H", pe, e+20)[0]
sec = e+24+so
for i in range(ns):
    o = sec+i*40
    if pe[o:o+5] == b".text":
        vs,va,rs,rp = struct.unpack_from("<IIII", pe, o+8); break
blob = bytearray(pe[rp:rp+rs])
n=0
for i in range(len(blob)-5):
    if blob[i]!=0xE8: continue
    rel=struct.unpack_from("<i",blob,i+1)[0]
    tgt=i+5+rel
    if not (0<=tgt<len(blob)-4): continue
    # mov rcx/rdx/r8/r9, imm32: 48 c7 c1/c2/c0/c0 variants
    for back in range(1, 7):
        at = tgt - back
        if at < 0: break
        if blob[at:at+3] in (b"\x48\xc7\xc1", b"\x48\xc7\xc2", b"\x48\xc7\xc0",
                              b"\x48\xc7\xc6", b"\x48\xc7\xc7", b"\x48\xc7\xc3"):
            if at + 7 > tgt:  # target inside this insn
                struct.pack_into("<i", blob, i+1, at - (i+5))
                n += 1
                break
print("mid-imm snaps", n)
pe[rp:rp+rs]=blob
pathlib.Path("build_univ227/cmd_univ2.exe").write_bytes(pe)
df.suppress_fault_ui()
exe=pathlib.Path("build_univ227/cmd_univ2.exe").resolve()
try:
 r=subprocess.run([str(exe),"/c","echo","w2ktest"],capture_output=True,timeout=25,cwd=str(exe.parent),creationflags=getattr(subprocess,"CREATE_NO_WINDOW",0))
 print("exit",hex(r.returncode&0xffffffff))
 print("out",repr(r.stdout[:600]))
 print(r.stdout.decode("utf-8","replace")[:500])
except subprocess.TimeoutExpired as ex:
 print("HANG",repr((ex.stdout or b"")[:500]))
