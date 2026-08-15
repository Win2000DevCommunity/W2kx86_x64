from pathlib import Path
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
import struct

pe=Path("build_univ96/cmd_pure.exe").read_bytes()
e=struct.unpack_from("<I",pe,0x3C)[0]
base=struct.unpack_from("<Q",pe,e+24+24)[0]
nsec=struct.unpack_from("<H",pe,e+6)[0]
osz=struct.unpack_from("<H",pe,e+20)[0]
soff=e+24+osz
for i in range(nsec):
    off=soff+i*40
    if pe[off:off+5]==b".text":
        vs,va,rs,rp=struct.unpack_from("<IIII",pe,off+8); break
rmap={}
for line in Path("build_univ96/rva.txt").read_text().splitlines():
    a,b=line.replace("->"," ").split()[:2]
    rmap[int(a,16)]=int(b,16)

md=Cs(CS_ARCH_X86,CS_MODE_64)
sites=[0xbc7d,0xb608,0xb60d,0xb47c,0xb542,0xb133,0xadc7,0xae1e]
for x in sites:
    r=rmap.get(x)
    print(f"\n=== x86 {x:#x} -> {r and hex(r)} ===")
    if not r: continue
    off=r-va
    for insn in md.disasm(pe[rp+off:rp+off+0x40], base+r):
        print(f"  {insn.address-base:#x}: {insn.mnemonic} {insn.op_str}")
        if insn.address>=base+r+0x30: break

# search for ANY imm 0x8001fbe2 in pe64
needle=struct.pack("<Q",0x8001fbe2)
needle32=struct.pack("<I",0x8001fbe2)
print("\nqword 8001fbe2 count", pe.count(needle), "dword", pe.count(needle32))
# also linear of fbe0
for v in (0x8001fbe2,0x8001fbe0,0x8001fbc8,0x8001fb80,0x8006cbe2,0x8006cbe0):
    print(hex(v), "q", pe.count(struct.pack("<Q",v)), "d", pe.count(struct.pack("<I",v)))

# find movabs with 8001xxxx that look like data
print("\nmovabs rax/r11 with 0x8001fxxx:")
code=pe[rp:rp+rs]
i=0
while i<len(code)-10:
    # 48/49 bb/b8
    if code[i] in (0x48,0x49) and code[i+1] in (0xb8,0xb9,0xba,0xbb,0xbe,0xbf):
        imm=struct.unpack_from("<Q",code,i+2)[0]
        if 0x8001f000 <= imm <= 0x8001ffff:
            print(f"  @{va+i:#x}: {code[i:i+10].hex()} imm={imm:#x}")
        i+=10
    else:
        i+=1
