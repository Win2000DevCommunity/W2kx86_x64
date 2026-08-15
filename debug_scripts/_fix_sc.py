import struct, pathlib
from x86x64.translator._healing import HealingMixin

# remove sc_flag from seed
path = pathlib.Path("x86x64/translator/_healing.py")
text = path.read_text(encoding="utf-8")
bad = """        helper += b'\\x41\\xc7\\x03\\x01\\x00\\x00\\x00'
        # /c SingleCommand (.data+0xF64) when PEB-seeded past /c.
        sc_flag = _find_data_va(_data_va(0xF64))
        helper += b'\\x49\\xbb' + struct.pack('<Q', sc_flag)
        helper += b'\\x41\\xc7\\x03\\x01\\x00\\x00\\x00'
        helper += b'\\x49\\xbb' + struct.pack('<Q', c8d8)"""
good = """        helper += b'\\x41\\xc7\\x03\\x01\\x00\\x00\\x00'
        helper += b'\\x49\\xbb' + struct.pack('<Q', c8d8)"""
if bad not in text:
    raise SystemExit("sc_flag block missing")
path.write_text(text.replace(bad, good, 1), encoding="utf-8")
print("removed sc_flag seed")

# find both dead sites on univ257
pe = bytearray(pathlib.Path("build_univ257/cmd_pure.exe").read_bytes())
e = struct.unpack_from("<I", pe, 0x3C)[0]
ns = struct.unpack_from("<H", pe, e + 6)[0]
so = struct.unpack_from("<H", pe, e + 20)[0]
sec = e + 24 + so
for i in range(ns):
    o = sec + i * 40
    if pe[o:o + 5] == b".text":
        vs, va, rs, rp = struct.unpack_from("<IIII", pe, o + 8)
        break
blob = pe[rp:rp + rs]
dead = bytes.fromhex("48894c240848895424104c894424184c894c242048c7c100000000c3")
idx = 0
while True:
    j = blob.find(dead, idx)
    if j < 0:
        break
    pad = blob[j+len(dead):j+len(dead)+8]
    callers = 0
    for off in range(len(blob) - 5):
        if blob[off] != 0xE8:
            continue
        rel = struct.unpack_from("<i", blob, off + 1)[0]
        if off + 5 + rel == j:
            callers += 1
    print(f"site {j+va:#x} pad={pad.hex()} callers={callers}")
    idx = j + 1
