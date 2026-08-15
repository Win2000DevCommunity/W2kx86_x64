import struct, pathlib
from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64
md32=Cs(CS_ARCH_X86, CS_MODE_32); md64=Cs(CS_ARCH_X86, CS_MODE_64)
src=pathlib.Path(r"C:\Users\win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU\cmd.exe").read_bytes()
pe=pathlib.Path("build_univ238/cmd_pure.exe").read_bytes()
# parse x86 sections
se=struct.unpack_from("<I",src,0x3C)[0]
ob=struct.unpack_from("<I",src,se+0x34)[0]
sns=struct.unpack_from("<H",src,se+6)[0]; sso=struct.unpack_from("<H",src,se+20)[0]; ssec=se+24+sso
for i in range(sns):
    o=ssec+i*40
    nm=src[o:o+8].split(b"\0")[0]
    vs,va,rs,rp=struct.unpack_from("<IIII",src,o+8)
    if nm.startswith(b".text"):
        tva,trp,trs=va,rp,rs; print("x86 text",hex(va),"base",hex(ob))
# find push of nearby code VAs around the x86 site that maps to 3624d
# Search for pattern: push imm; push imm near message 0x2d
# Or find absolute  that becomes 594f6
# pe64 0x594f6 = data+0x14f6; x86 data 0x1c000+0x14f6=0x1d4f6
# Check if x86 has code pointer at that data slot
for i in range(sns):
    o=ssec+i*40
    nm=src[o:o+8].split(b"\0")[0]
    vs,va,rs,rp=struct.unpack_from("<IIII",src,o+8)
    if nm.startswith(b".data"):
        slot=src[rp+0x14f6:rp+0x14f6+4]
        print("x86[.data+14f6]=",slot.hex(), "as va", hex(struct.unpack("<I",slot)[0]))
# Search x86 for push of code addresses near 0x2d immediate
hits=[]
for off in range(trs-10):
    if src[trp+off]==0x6A and src[trp+off+1]==0x2d:  # push 0x2d
        hits.append(tva+off)
    if src[trp+off:trp+off+2]==b"\x6a\x2d":
        hits.append(tva+off)
print("push 0x2d at", [hex(h) for h in hits[:20]])
for h in hits[:5]:
    o=trp+(h-tva)-20
    print(f"\n--- around {h:#x} ---")
    for insn in md32.disasm(src[o:o+60], ob+h-20):
        print(f"  {insn.address:#x}: {insn.mnemonic} {insn.op_str}")
