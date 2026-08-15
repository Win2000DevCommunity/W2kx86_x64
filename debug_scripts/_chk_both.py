# Quick patch univ225: F4EB retarget + fd5d arg4 REX restore, then smoke
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

# 1) retarget 45862 -> 1d35c
call_at = 0x45862 - va
struct.pack_into("<i", blob, call_at + 1, 0x1d35c - (0x45862 + 5))

# 2) apply arg4 heal
from x86x64.translator import Win2000Translator
# minimal: inline the heal logic
sig = bytes.fromhex("4c894d285356574889c748897d28")
at = blob.find(sig)
print("sig2 at", hex(at+va) if at>=0 else None)
if at >= 0:
    patch_at = at + 7
    store_len = 7
    stub = bytearray()
    stub += b"\x48\x83\xec\x20\xff\x55\x28\x48\x83\xc4\x20\x89\xc7\x48\x89\x7d\x28"
    pad_at = len(blob)
    blob.extend(b"\x00" * (len(stub) + 5))
    ret_at = patch_at + store_len
    stub += b"\xe9" + struct.pack("<i", ret_at - (pad_at + len(stub) + 5))
    blob[pad_at:pad_at+len(stub)] = stub
    jmp = bytearray(b"\xe9" + struct.pack("<i", pad_at - (patch_at + 5)))
    while len(jmp) < store_len:
        jmp.append(0x90)
    blob[patch_at:patch_at+store_len] = jmp

pe[rp:rp+len(blob)] = blob
# grow .text if needed - for simplicity write full file with extended blob
# if blob grew past rs, we need section update - check
print("blob len", len(blob), "rs", rs)
if len(blob) > rs:
    # append to end of file and update section size - crude
    pe[rp:rp+rs] = blob[:rs]
    print("WARNING truncated - use full rebuild")
else:
    pe[rp:rp+rs] = blob
    pathlib.Path("build_univ225/cmd_both.exe").write_bytes(pe)
    df.suppress_fault_ui()
    exe = pathlib.Path("build_univ225/cmd_both.exe").resolve()
    try:
        r = subprocess.run([str(exe), "/c", "echo", "w2ktest"], capture_output=True,
                           timeout=20, cwd=str(exe.parent),
                           creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        print("exit", hex(r.returncode & 0xFFFFFFFF))
        print("out", repr(r.stdout[:300]))
    except subprocess.TimeoutExpired as ex:
        print("HANG", repr((ex.stdout or b"")[:300]))
