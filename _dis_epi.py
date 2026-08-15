import pefile, struct
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
pe = pefile.PE("build_univ256/cmd_probe_pushrcx.exe")
md = Cs(CS_ARCH_X86, CS_MODE_64)
base = 0x80000000
print("--- 18E62 to epilogue ---")
for i in md.disasm(pe.get_data(0x18E62, 0x80), base+0x18E62):
    print(f"  {i.address-base:06X}: {i.bytes.hex():28s} {i.mnemonic} {i.op_str}")
    if i.mnemonic == "ret" or (i.mnemonic == "jmp" and "0x80037" in i.op_str):
        break
# find e9 to 37e68
text=bytearray(pe.get_data(0x1000,0x57000))
print("--- jmps to epi cave region ---")
for off in range(len(text)-5):
    if text[off]==0xe9:
        rel=struct.unpack_from("<i",text,off+1)[0]
        dest=off+5+rel
        if 0x37e60 <= dest+0x1000 <= 0x37e70 or 0x27e60 <= dest <= 0x27e70:
            print(f"  jmp at {off+0x1000:#x} -> {dest+0x1000:#x}")
# also check callee for mov rbp
print("--- callee 4276c body looking for rbp ---")
for i in md.disasm(pe.get_data(0x4276C, 0x200), base+0x4276C):
    if "rbp" in i.op_str or i.mnemonic in ("leave","enter"):
        print(f"  {i.address-base:06X}: {i.mnemonic} {i.op_str}")
    if i.mnemonic=="ret" and i.address>base+0x42800:
        break
