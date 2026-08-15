import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
pe = pefile.PE("build_univ258/cmd_probe_jcc.exe")
md = Cs(CS_ARCH_X86, CS_MODE_64)
print("=== 47120-47160 (ret AV) ===")
for i in md.disasm(pe.get_data(0x470F0, 0x80), 0x800470F0):
    print(f"  {i.address-0x80000000:06X}: {i.mnemonic} {i.op_str}")

print("\n=== 20A0 (ret addr) ===")
for i in md.disasm(pe.get_data(0x2080, 0x40), 0x80002080):
    print(f"  {i.address-0x80000000:06X}: {i.mnemonic} {i.op_str}")

# 0x495098 as ascii?
v=0x495098
print('as ascii fragments', bytes([(v>>16)&0xff,(v>>8)&0xff,v&0xff]))
# Maybe it's a VA truncated - 800495098?
