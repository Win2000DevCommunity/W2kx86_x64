from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_MODE_32
import struct, pathlib, subprocess, sys
sys.path.insert(0, ".")
import dbg_fault as df

# x86 fbe4 full tip
x86 = bytearray(pathlib.Path(r"C:\Users\win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU\cmd.exe").read_bytes())
e = struct.unpack_from("<I", x86, 0x3C)[0]
ns = struct.unpack_from("<H", x86, e+6)[0]
so = struct.unpack_from("<H", x86, e+20)[0]
sec = e+24+so
for i in range(ns):
    o = sec+i*40
    if x86[o:o+5] == b".text":
        vs,va32,rs,rp = struct.unpack_from("<IIII", x86, o+8)
        xt = bytes(x86[rp:rp+rs]); tr = va32; break
print("x86 fbe4 bytes", xt[0xfbe4-tr:0xfbe4-tr+16].hex())
# callers of fbe4
for i in range(len(xt)-5):
    if xt[i]!=0xE8: continue
    rel=struct.unpack_from("<i",xt,i+1)[0]
    if (tr+i+5+rel)&0xffffffff == 0xfbe4:
        print("x86 caller", hex(tr+i))

pe = bytearray(pathlib.Path("build_univ227/cmd_fix.exe").read_bytes())
e = struct.unpack_from("<I", pe, 0x3C)[0]
ns = struct.unpack_from("<H", pe, e+6)[0]
so = struct.unpack_from("<H", pe, e+20)[0]
sec = e+24+so
for i in range(ns):
    o = sec+i*40
    if pe[o:o+5] == b".text":
        vs,va,rs,rp = struct.unpack_from("<IIII", pe, o+8); break
blob = bytearray(pe[rp:rp+rs])
# retarget callers of 1e28d -> 1e2c0 (home-spill entry)
new_tgt = 0x1e2c0
for call_rva in (0x1d5dd, 0x1d71c, 0x1e257):
    off = call_rva - va
    old = call_rva+5+struct.unpack_from("<i",blob,off+1)[0]
    struct.pack_into("<i", blob, off+1, new_tgt - (call_rva+5))
    print("retarget", hex(call_rva), hex(old), "->", hex(new_tgt))
pe[rp:rp+rs] = blob
pathlib.Path("build_univ227/cmd_fbe4.exe").write_bytes(pe)
df.suppress_fault_ui()
exe = pathlib.Path("build_univ227/cmd_fbe4.exe").resolve()
try:
    r = subprocess.run([str(exe),"/c","echo","w2ktest"], capture_output=True, timeout=25,
                       cwd=str(exe.parent), creationflags=getattr(subprocess,"CREATE_NO_WINDOW",0))
    print("exit", hex(r.returncode & 0xFFFFFFFF))
    print("out", repr(r.stdout[:500]))
except subprocess.TimeoutExpired as ex:
    print("HANG", repr((ex.stdout or b"")[:500]))
