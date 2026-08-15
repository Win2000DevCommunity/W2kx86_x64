from pathlib import Path
from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64
import struct

src=Path(r"C:\Users\win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU\cmd.exe").read_bytes()
e=struct.unpack_from("<I",src,0x3C)[0]
base32=struct.unpack_from("<I",src,e+24+28)[0]
nsec=struct.unpack_from("<H",src,e+6)[0]
osz=struct.unpack_from("<H",src,e+20)[0]
soff=e+24+osz
for i in range(nsec):
    off=soff+i*40
    name=src[off:off+8].split(b"\0",1)[0]
    vsz,va,rsz,raw=struct.unpack_from("<IIII",src,off+8)
    if name==b".text": va32,raw32,rsz32=va,raw,rsz
    if name==b".data": print("data",hex(va),hex(vsz))

md=Cs(CS_ARCH_X86,CS_MODE_32)
print("=== adad x86 ===")
fo=raw32+(0xadad-va32)
for insn in md.disasm(src[fo:fo+0xc0], base32+0xadad):
    print(f"  {insn.address-base32:#x}: {insn.mnemonic} {insn.op_str}")
    if insn.address>=base32+0xadad+0xb0: break

# stores to fbc8
print("\n=== stores involving fbc8 / fbe2 ===")
blob=src[raw32:raw32+rsz32]
for needle,lab in [(0x4ad1fbc8,"fbc8"),(0x4ad1fbe2,"fbe2"),(0x4ad21000,"21000")]:
    pat=struct.pack("<I",needle)
    idx=0
    while True:
        j=blob.find(pat,idx)
        if j<0: break
        # back up to insn start roughly
        start=max(0,j-2)
        for insn in md.disasm(blob[start:start+16], base32+va32+start):
            if pat.hex() in insn.bytes.hex() or lab in insn.op_str or hex(needle)[2:] in insn.op_str:
                print(f"  {lab} @{insn.address-base32:#x}: {insn.mnemonic} {insn.op_str}  [{insn.bytes.hex()}]")
                break
        idx=j+1

# pe64 adad
pe=Path("build_univ96/cmd_pure.exe").read_bytes() if Path("build_univ96/cmd_pure.exe").exists() else Path("build_univ95/cmd_pure.exe").read_bytes()
e=struct.unpack_from("<I",pe,0x3C)[0]
base=struct.unpack_from("<Q",pe,e+24+24)[0]
nsec=struct.unpack_from("<H",pe,e+6)[0]
osz=struct.unpack_from("<H",pe,e+20)[0]
soff=e+24+osz
rmap={}
rva_path=Path("build_univ96/rva.txt") if Path("build_univ96/rva.txt").exists() else Path("build_univ95/rva.txt")
for line in rva_path.read_text().splitlines():
    a,b=line.replace("->"," ").split()[:2]
    rmap[int(a,16)]=int(b,16)
print("\nadad->",hex(rmap.get(0xadad,-1)), "ae1e->",hex(rmap.get(0xae1e,-1)))
for i in range(nsec):
    off=soff+i*40
    if pe[off:off+5]==b".text":
        vs,va,rs,rp=struct.unpack_from("<IIII",pe,off+8); break
md64=Cs(CS_ARCH_X86,CS_MODE_64)
rva=rmap.get(0xadad,0)
off=rva-va
print(f"\n=== pe64 adad @{rva:#x} ===")
for insn in md64.disasm(pe[rp+off:rp+off+0x150], base+rva):
    print(f"  {insn.address-base:#x}: {insn.mnemonic} {insn.op_str}")
    if insn.address>=base+rva+0x140: break
