import struct, pathlib
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

pe = pathlib.Path("build_univ53/cmd_heal2.exe").read_bytes()
# PE parse minimal
e_lfanew = struct.unpack_from("<I", pe, 0x3C)[0]
opt = e_lfanew + 24
magic = struct.unpack_from("<H", pe, opt)[0]
assert magic == 0x20B
image_base = struct.unpack_from("<Q", pe, opt + 24)[0]
num_sec = struct.unpack_from("<H", pe, e_lfanew + 6)[0]
size_opt = struct.unpack_from("<H", pe, e_lfanew + 20)[0]
sec_off = e_lfanew + 24 + size_opt
sections = []
for i in range(num_sec):
    o = sec_off + i*40
    name = pe[o:o+8].split(b"\0",1)[0].decode()
    vsz, va, rsz, raw = struct.unpack_from("<IIII", pe, o+8)
    sections.append((name, va, vsz, raw, rsz))
    print(f"sec {name:8} va={va:#x} vsz={vsz:#x} raw={raw:#x} rsz={rsz:#x}")

def rva_to_off(rva):
    for name, va, vsz, raw, rsz in sections:
        if va <= rva < va + max(vsz, rsz):
            return raw + (rva - va), name
    return None, None

md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True

# load rva map reverse: new_off -> old_rva (approx)
rmap = {}
for line in open("build_univ53/rva.txt"):
    a,b = line.split()
    rmap[int(a,16)] = int(b,16)  # x86_rva -> new_off_or_rva?

# check a few keys
sample = list(rmap.items())[:3]
print("rva sample", [(hex(a),hex(b)) for a,b in sample])
# values look like offsets into text (small) or VAs?
vals = [v for v in rmap.values()]
print("val range", hex(min(vals)), hex(max(vals)))

def disasm_rva(rva, n=24, back=16):
    off, name = rva_to_off(rva)
    if off is None:
        print(f"no mapping for {rva:#x}"); return
    start = max(0, off - back)
    blob = pe[start:off+64]
    base_rva = rva - (off - start)
    print(f"\n=== disasm around rva {rva:#x} ({name}) ===")
    for insn in md.disasm(blob, image_base + base_rva):
        mark = ">>" if insn.address == image_base + rva else "  "
        print(f"{mark}{insn.address:#x}: {insn.mnemonic} {insn.op_str}")
        n -= 1
        if n <= 0: break

for r in [0x6C860, 0x16871, 0x704A0, 0x55DF8, 0x32267, 0x80507, 0x6E320, 0x6E378]:
    disasm_rva(r, n=20, back=32)

# find x86 sources for code RVAs via reverse map (value==rva or value==rva for text offs)
# rva_map values may be text offsets; text starts at 0x1000
text_va = [s for s in sections if s[0].startswith(".text")][0][1]
print("text_va", hex(text_va))

def find_x86(new_rva, window=8):
    # try as offset into text
    candidates = []
    for xr, nv in rmap.items():
        # nv might be text offset or full rva
        if abs((nv if nv < 0x100000 else nv) - (new_rva if new_rva < 0x100000 else new_rva - text_va)) <= window:
            candidates.append((xr, nv, abs(nv - (new_rva - text_va if new_rva >= text_va else new_rva))))
        if abs(nv - new_rva) <= window:
            candidates.append((xr, nv, abs(nv - new_rva)))
    candidates.sort(key=lambda t: t[2])
    return candidates[:8]

for r in [0x6C860, 0x16871, 0x55DF8, 0x32267]:
    print(f"x86 near {r:#x}:", [(hex(a),hex(b),d) for a,b,d in find_x86(r)])
