import struct, pathlib
from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64

# Map PE64 offs 0x119xx -> x86 via rva.txt
rmap = {}
for line in open("build_univ53/rva.txt"):
    a,b = line.split()
    rmap[int(a,16)] = int(b,16)

# reverse: new -> list of x86
rev = {}
for xr, nv in rmap.items():
    rev.setdefault(nv, []).append(xr)

def x86_near(new_off, w=4):
    hits=[]
    for d in range(-w,w+1):
        hits.extend((new_off+d, xr) for xr in rev.get(new_off+d, []))
    return sorted(hits)

for off in [0x1191f, 0x11968, 0x1196f, 0x11999, 0x119a8, 0x119be, 0x14d69, 0x14d19]:
    print(hex(off), "<-", [hex(x) for _,x in x86_near(off, 6)][:12])

src = pathlib.Path(r"C:\Users\win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU\cmd.exe").read_bytes()
e = struct.unpack_from("<I", src, 0x3C)[0]
opt = e+24
ib = struct.unpack_from("<I", src, opt+28)[0]
nsec = struct.unpack_from("<H", src, e+6)[0]
szopt = struct.unpack_from("<H", src, e+20)[0]
soff = e+24+szopt
text_va=text_raw=None
for i in range(nsec):
    o=soff+i*40
    name=src[o:o+8].split(b"\0",1)[0]
    vsz,va,rsz,raw=struct.unpack_from("<IIII", src, o+8)
    if name.startswith(b".text"):
        text_va, text_raw, text_rsz = va, raw, rsz
        break
text = src[text_raw:text_raw+text_rsz]
md=Cs(CS_ARCH_X86, CS_MODE_32)
md.detail=True

def dis_x86(rva, n=40, back=0x30):
    fo = rva - text_va
    start = max(0, fo-back)
    print(f"\n=== x86 @{rva:#x} ===")
    for insn in md.disasm(text[start:fo+80], ib+text_va+start):
        mark=">>" if insn.address==ib+rva else "  "
        print(f"{mark}{insn.address:#x}: {insn.mnemonic} {insn.op_str}")
        n-=1
        if n<=0: break

# find x86 for 119a8 region - try closest
for off in range(0x11900, 0x119d0):
    if off in rev:
        pass
# print denser map
print("\nmap dens 0x118f0-0x11a00:")
for off in range(0x118f0, 0x11a20):
    if off in rev:
        print(f"  {off:#x} <- {[hex(x) for x in rev[off]]}")

# also find all calls to 0xb627 in x86
print("\ncalls to 0xb627:")
for fo in range(len(text)-5):
    if text[fo]==0xE8:
        rel=struct.unpack_from("<i", text, fo+1)[0]
        tgt=(text_va+fo+5+rel)&0xffffffff
        if tgt==0xb627:
            print(f"  call @ {text_va+fo:#x}")
            dis_x86(text_va+fo, n=25, back=0x40)

dis_x86(0xb627, n=15, back=0)
