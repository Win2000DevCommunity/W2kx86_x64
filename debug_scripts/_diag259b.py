import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
pe = pefile.PE("build_univ259/cmd_pure.exe")
md = Cs(CS_ARCH_X86, CS_MODE_64)
print("=== 17624 ===")
for i in md.disasm(pe.get_data(0x17624, 0x60), 0x80017624):
    print(f"  {i.address-0x80000000:06X}: {i.mnemonic} {i.op_str}")
    if i.mnemonic=='ret' and i.address>0x80017650:
        break

# CRT entry / PE entry
print("\n=== entry 33EC4 ===")
for i in md.disasm(pe.get_data(0x33EC4, 0x40), 0x80033EC4):
    print(f"  {i.address-0x80000000:06X}: {i.mnemonic} {i.op_str}")

# Compare 258 vs 259 at early init - what calls null?
# Look at IAT 85550 from 34179
print("\nIAT 85550")
ppe=pe
for e in ppe.DIRECTORY_ENTRY_IMPORT:
  for imp in e.imports:
    if imp.address and (imp.address - 0x80000000)==0x85550:
      print(e.dll, imp.name)
