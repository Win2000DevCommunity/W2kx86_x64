import struct, pathlib, subprocess, sys
sys.path.insert(0, ".")
import dbg_fault as df

pe = bytearray(pathlib.Path("build_univ225/cmd_pure.exe").read_bytes())
e = struct.unpack_from("<I", pe, 0x3C)[0]
ns = struct.unpack_from("<H", pe, e+6)[0]
so = struct.unpack_from("<H", pe, e+20)[0]
sec = e+24+so
for i in range(ns):
    o = sec+i*40
    if pe[o:o+5] == b".text":
        vs,va,rs,rp = struct.unpack_from("<IIII", pe, o+8); break
blob = bytearray(pe[rp:rp+rs])

# retarget F4EB
struct.pack_into("<i", blob, 0x45862 - va + 1, 0x1d35c - (0x45862 + 5))

sig = bytes.fromhex("4c894d285356574889c748897d28")
at = blob.find(sig)
patch_at = at + 7
store_len = 7
stub = bytearray(b"\x48\x83\xec\x20\xff\x55\x28\x48\x83\xc4\x20\x89\xc7\x48\x89\x7d\x28")
need = len(stub) + 5
# find pad
pad_at = None
run = 0
for p in range(len(blob) - 1, max(0, len(blob) - 0x10000), -1):
    if blob[p] in (0x00, 0x90, 0xCC):
        run += 1
        if run >= need and abs(p - patch_at) > 0x20:
            pad_at = p
            break
    else:
        run = 0
print("pad", hex(pad_at+va) if pad_at is not None else None, "need", need)
ret_at = patch_at + store_len
stub += b"\xe9" + struct.pack("<i", ret_at - (pad_at + len(stub) + 5))
blob[pad_at:pad_at+len(stub)] = stub
jmp = bytearray(b"\xe9" + struct.pack("<i", pad_at - (patch_at + 5)))
while len(jmp) < store_len:
    jmp.append(0x90)
blob[patch_at:patch_at+store_len] = jmp
pe[rp:rp+rs] = blob
pathlib.Path("build_univ225/cmd_both.exe").write_bytes(pe)

df.suppress_fault_ui()
exe = pathlib.Path("build_univ225/cmd_both.exe").resolve()
try:
    r = subprocess.run([str(exe), "/c", "echo", "w2ktest"], capture_output=True,
                       timeout=20, cwd=str(exe.parent),
                       creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    print("exit", hex(r.returncode & 0xFFFFFFFF))
    print("out", repr(r.stdout[:400]))
except subprocess.TimeoutExpired as ex:
    print("HANG", repr((ex.stdout or b"")[:400]))
