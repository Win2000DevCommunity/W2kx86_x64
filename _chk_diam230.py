from capstone import Cs, CS_ARCH_X86, CS_MODE_64
import struct, pathlib
for name in ["build_univ230/cmd_pure.exe","build_univ230/cmd_debs.exe","build_univ229/cmd_diam.exe"]:
    pe=bytearray(pathlib.Path(name).read_bytes())
    e=struct.unpack_from("<I",pe,0x3C)[0]
    ns=struct.unpack_from("<H",pe,e+6)[0]; so=struct.unpack_from("<H",pe,e+20)[0]; sec=e+24+so
    ib=struct.unpack_from("<Q",pe,e+24+24)[0]
    for i in range(ns):
        o=sec+i*40
        if pe[o:o+5]==b".text":
            vs,va,rs,rp=struct.unpack_from("<IIII",pe,o+8); break
    code=bytes(pe[rp:rp+rs]); md=Cs(CS_ARCH_X86,CS_MODE_64)
    print(f"\n==== {name} diamonds ====")
    for tip in [0x3624d, 0x1d4f4, 0x1d534, 0x1d574]:
        print(f" -- tip {tip:#x} --")
        for i, insn in enumerate(md.disasm(code[tip-va:tip-va+0x40], ib+tip)):
            if insn.mnemonic=="movabs" and any(r in insn.op_str for r in ("r8","r9","rcx")):
                print(f"  {insn.address:#x}: {insn.mnemonic} {insn.op_str}")
            if i>20: break
# fault 594f6
print("\n==== what is 594f6 ====")
pe=bytearray(pathlib.Path("build_univ230/cmd_debs.exe").read_bytes())
e=struct.unpack_from("<I",pe,0x3C)[0]
ns=struct.unpack_from("<H",pe,e+6)[0]; so=struct.unpack_from("<H",pe,e+20)[0]; sec=e+24+so
for i in range(ns):
    o=sec+i*40
    name=pe[o:o+8].split(b"\0")[0]
    vs,va,rs,rp=struct.unpack_from("<IIII",pe,o+8)
    if va <= 0x594f6 < va+vs:
        print(name, "rva", hex(0x594f6), "contains fault")
        off=rp+(0x594f6-va)
        print("bytes", pe[off:off+16].hex())
