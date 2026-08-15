import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
pe = pefile.PE("build_univ258/cmd_probe_jcc.exe")
md=Cs(CS_ARCH_X86,CS_MODE_64)
for h in [0x1d5b4, 0x1d6e0, 0x1e220]:
  print(f"\n=== {h:06X} ===")
  for i in md.disasm(pe.get_data(h, 0x60), 0x80000000+h):
    print(f"  {i.address-0x80000000:06X}: {i.mnemonic} {i.op_str}")
    if i.address > 0x80000000+h+0x50:
      break

# Does 1E2B4 ever call 1d71c or 1e257 or 1e62c?
# Already saw call 36235, 1ea3c, 14974, 19dc4, 260fc, 1ec50, 3498d, 1e968
# Check 1e257 region - is it inside another function that 1E2B4 reaches via 1e968?
print("\n=== 1E968 ===")
for i in md.disasm(pe.get_data(0x1E968, 0x40), 0x8001E968):
  print(f"  {i.address-0x80000000:06X}: {i.mnemonic} {i.op_str}")
