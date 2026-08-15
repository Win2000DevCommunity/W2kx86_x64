import struct, pathlib
from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64

src = pathlib.Path(r"C:\Users\win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU\cmd.exe").read_bytes()
e = struct.unpack_from("<I", src, 0x3C)[0]
opt = e+24
ib = struct.unpack_from("<I", src, opt+28)[0]
nsec = struct.unpack_from("<H", src, e+6)[0]
szopt = struct.unpack_from("<H", src, e+20)[0]
soff = e+24+szopt
secs=[]
for i in range(nsec):
    o=soff+i*40
    name=src[o:o+8].split(b"\0",1)[0]
    vsz,va,rsz,raw=struct.unpack_from("<IIII", src, o+8)
    secs.append((name,va,vsz,raw,rsz))
print("x86 base", hex(ib), secs)

# search UTF-16 "echo" in .data
needle = "echo".encode("utf-16le")
idx=0
hits=[]
while True:
    j=src.find(needle, idx)
    if j<0: break
    hits.append(j)
    idx=j+2
print("echo string file offs", [hex(h) for h in hits[:10]])

def fo_to_va(fo):
    for name,va,vsz,raw,rsz in secs:
        if raw <= fo < raw+rsz:
            return ib+va+(fo-raw)
    return None

for h in hits[:5]:
    print(hex(h), "va", hex(fo_to_va(h) or 0))

# find "ECHO" command table entry patterns: ptr to name, ptr to handler
# common: dd offset aEcho; dd offset EchoCmd; ...
md=Cs(CS_ARCH_X86,CS_MODE_32)
# search for reloc/data pointing to echo string va
echo_vas=[fo_to_va(h) for h in hits if fo_to_va(h)]
print("echo vas", [hex(v) for v in echo_vas])

pe64=pathlib.Path("build_univ53/cmd_heal2.exe").read_bytes()
# search for call rdi = ff d7, call rax = ff d0 in .text
e2=struct.unpack_from("<I", pe64, 0x3C)[0]
opt2=e2+24
ib2=struct.unpack_from("<Q", pe64, opt2+24)[0]
nsec2=struct.unpack_from("<H", pe64, e2+6)[0]
szopt2=struct.unpack_from("<H", pe64, e2+20)[0]
soff2=e2+24+szopt2
for i in range(nsec2):
    o=soff2+i*40
    name=pe64[o:o+8].split(b"\0",1)[0]
    if name.startswith(b".text"):
        va,rsz,raw=struct.unpack_from("<III", pe64, o+12)[0], struct.unpack_from("<I", pe64, o+16)[0], struct.unpack_from("<I", pe64, o+20)[0]
        text=pe64[raw:raw+rsz]
        text_va=struct.unpack_from("<I", pe64, o+12)[0]
        break

# count call rdi / call rax
for pat,lab in [(b"\xff\xd7","call rdi"), (b"\xff\xd0","call rax"), (b"\xff\xd6","call rsi"), (b"\x41\xff\xd0","call r8"), (b"\x41\xff\xd1","call r9"), (b"\x41\xff\xd2","call r10"), (b"\x41\xff\xd3","call r11")]:
    c=0
    i=0
    while True:
        j=text.find(pat,i)
        if j<0: break
        c+=1
        i=j+1
    print(lab, c)

# disasm around call rdi sites that are near 0x27xxx / dispatch
md64=Cs(CS_ARCH_X86,CS_MODE_64)
# find mov rdi from mem then call rdi nearby
sites=[]
i=0
while True:
    j=text.find(b"\xff\xd7", i)
    if j<0: break
    # look back 40 bytes for mov rdi,
    window=text[max(0,j-48):j+2]
    for insn in md64.disasm(window, ib2+text_va+max(0,j-48)):
        pass
    sites.append(j)
    i=j+1
print("call rdi sites", len(sites), "first rvas", [hex(text_va+s) for s in sites[:15]])

# dump context for each call rdi
for s in sites[:20]:
    start=max(0,s-40)
    print(f"\n--- call rdi @ {text_va+s:#x} ---")
    for insn in md64.disasm(text[start:s+8], ib2+text_va+start):
        mark=">>" if insn.address==ib2+text_va+s else "  "
        print(f"{mark}{insn.address:#x}: {insn.mnemonic} {insn.op_str}")
