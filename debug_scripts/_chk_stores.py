from capstone import Cs, CS_ARCH_X86, CS_MODE_64
import struct, pathlib
pe = bytearray(pathlib.Path("build_univ229/cmd_diam.exe").read_bytes())
e = struct.unpack_from("<I", pe, 0x3C)[0]
ns = struct.unpack_from("<H", pe, e+6)[0]
so = struct.unpack_from("<H", pe, e+20)[0]
sec = e+24+so
ib = struct.unpack_from("<Q", pe, e+24+24)[0]
for i in range(ns):
    o = sec+i*40
    if pe[o:o+5] == b".text":
        vs,va,rs,rp = struct.unpack_from("<IIII", pe, o+8); break
code = bytes(pe[rp:rp+rs])
md = Cs(CS_ARCH_X86, CS_MODE_64)
print("Stores involving rbp+0x10..0x28 in fn 249e8..24e20:")
for insn in md.disasm(code[0x249e8-va:0x24e20-va], ib+0x249e8):
    if insn.mnemonic.startswith("mov") and "rbp +" in insn.op_str:
        # store if rbp is dest
        if insn.op_str.startswith("qword ptr [rbp") or insn.op_str.startswith("dword ptr [rbp") or insn.op_str.startswith("word ptr [rbp") or insn.op_str.startswith("byte ptr [rbp"):
            print(f"  {insn.address:#x}: {insn.mnemonic} {insn.op_str}")
print("\nAll rbp+/- refs that are stores (dest first):")
for insn in md.disasm(code[0x249e8-va:0x24e20-va], ib+0x249e8):
    ops=insn.op_str
    if insn.mnemonic.startswith("mov") and ops.startswith(("qword ptr [rbp","dword ptr [rbp","word ptr [rbp","byte ptr [rbp")):
        print(f"  {insn.address:#x}: {insn.mnemonic} {ops}")
