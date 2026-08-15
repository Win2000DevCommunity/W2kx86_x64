import os, struct, shutil, subprocess, pathlib
ROOT = pathlib.Path(r"c:\Users\win2000\Desktop\Nouveau dossier\Nouveau dossier (9)\X86_X64")
src = ROOT / "build_univ249" / "cmd_pure.exe"
dst = ROOT / "build_univ249" / "cmd_probe8.exe"
shutil.copy2(src, dst)
pe = bytearray(dst.read_bytes())
e = struct.unpack_from("<I", pe, 0x3C)[0]
ns = struct.unpack_from("<H", pe, e + 6)[0]
so = struct.unpack_from("<H", pe, e + 20)[0]
sec = e + 24 + so
for i in range(ns):
    o = sec + i * 40
    if pe[o:o+5] == b".text":
        vs, va, rs, rp = struct.unpack_from("<IIII", pe, o + 8)
        break
nb = 0x80000000

def off(rva):
    return rp + (rva - va)

def find_pad(need):
    for i in range(rp + rs - need - 0x40, rp + rs - need):
        if all(b in (0x00, 0xCC) for b in pe[i:i+need]):
            return i
    for i in range(rp, rp + rs - need):
        if pe[i:i+need] == b"\x00" * need:
            return i
    raise SystemExit("no pad")

for rva, val in {
    0x1D50F: nb + 0x1D534,
    0x1D545: nb + 0x1D534,
    0x1D54F: nb + 0x1D574,
    0x1D585: nb + 0x1D574,
}.items():
    struct.pack_into("<Q", pe, off(rva) + 2, val)

struct.pack_into("<i", pe, off(0x1D62A) + 2, 0x1D6CB - (0x1D62A + 6))

and_at = off(0x24AEA)
assert pe[and_at:and_at+5] == bytes.fromhex("668365e400")
cave_and = find_pad(14)
stub = bytearray(bytes.fromhex("6683645de400"))
stub += b"\xe9" + struct.pack("<i", (and_at + 5) - (cave_and + 11))
pe[cave_and:cave_and+11] = stub
pe[and_at:and_at+5] = b"\xe9" + struct.pack("<i", cave_and - (and_at + 5))

ADD = bytes.fromhex("4883451002")

mov_at = off(0x24CF8)
assert pe[mov_at:mov_at+7] == bytes.fromhex("c745fc01000000")
pad = find_pad(48)
cave_skip = pad
cave_add = pad + 20
code_skip = bytes.fromhex("c745fc01000000") + b"\xe9" + struct.pack("<i", off(0x24CFF) - (cave_skip + 12))
code_add = ADD + b"\xe9" + struct.pack("<i", cave_skip - (cave_add + 10))
pe[cave_skip:cave_skip+len(code_skip)] = code_skip
pe[cave_add:cave_add+len(code_add)] = code_add
for jcc_rva in (0x24CE9, 0x24CF2):
    j = off(jcc_rva)
    struct.pack_into("<i", pe, j + 2, cave_skip - (j + 6))
pe[mov_at:mov_at+5] = b"\xe9" + struct.pack("<i", cave_add - (mov_at + 5))
pe[mov_at+5:mov_at+7] = b"\x90\x90"

insert_after = []
for rva in range(0x24D40, 0x24DE0):
    o = off(rva)
    if pe[o:o+3] == bytes.fromhex("668901"):
        insert_after.append(rva + 3)
        print("store", hex(rva))

for end_rva in insert_after:
    o = off(end_rva)
    saved = bytes(pe[o:o+5])
    cave = find_pad(5 + len(ADD) + 5 + 8)
    stub = bytearray(ADD)
    stub += saved
    stub += b"\xe9" + struct.pack("<i", (o + 5) - (cave + len(stub) + 5))
    pe[cave:cave+len(stub)] = stub
    pe[o:o+5] = b"\xe9" + struct.pack("<i", cave - (o + 5))

head = off(0x24D4B)
jcc = off(0x24D45)
assert pe[jcc:jcc+2] == bytes.fromhex("0f85")
cave_pre = find_pad(20)
code_pre = ADD + b"\xe9" + struct.pack("<i", head - (cave_pre + 10))
pe[cave_pre:cave_pre+len(code_pre)] = code_pre
struct.pack_into("<i", pe, jcc + 2, cave_pre - (jcc + 6))
pe[jcc+1] = 0x84

dst.write_bytes(pe)
env = os.environ.copy()
env["PATH"] = str(dst.parent) + ";" + env.get("PATH", "")
p = subprocess.run([str(dst), "/c", "echo", "w2ktest"], capture_output=True, timeout=12, env=env)
print("rc", hex(p.returncode & 0xffffffff))
print("out", p.stdout[:600])
print("err", p.stderr[:400])
