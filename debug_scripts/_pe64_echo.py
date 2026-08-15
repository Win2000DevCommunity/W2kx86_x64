import struct, pathlib
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
md=Cs(CS_ARCH_X86, CS_MODE_64)
pe=pathlib.Path("build_univ230/cmd_fix20.exe").read_bytes()
e=struct.unpack_from("<I",pe,0x3C)[0]
ns=struct.unpack_from("<H",pe,e+6)[0]; so=struct.unpack_from("<H",pe,e+20)[0]; sec=e+24+so
for i in range(ns):
    o=sec+i*40
    if pe[o:o+5]==b".text":
        vs,va,rs,rp=struct.unpack_from("<IIII",pe,o+8); break
print("=== eEcho 0x189c4 (calls / cmp -1 / lea rdx) ===")
for insn in md.disasm(pe[rp+(0x189c4-va):rp+(0x18e40-va)], 0x80000000+0x189c4):
    s=f"{insn.mnemonic} {insn.op_str}"
    if (insn.mnemonic in ("call",) or "0xffffffff" in s or "lea" in s
            or insn.mnemonic.startswith("j") or "[rbx + 0x38]" in s):
        print(f"  {insn.address:#x}: {s}")
