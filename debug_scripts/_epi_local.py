import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
pe = pefile.PE("build_univ258/cmd_probe_lj.exe")
md=Cs(CS_ARCH_X86,CS_MODE_64)
# find pop rsi; pop rbx; pop rbp; ret near 1C5F8 function
print("=== scan 1C720-1C800 for epi ===")
for i in md.disasm(pe.get_data(0x1C720, 0x100), 0x8001C720):
    print(f"  {i.address-0x80000000:06X}: {i.mnemonic} {i.op_str}")
    if i.mnemonic=='ret' and i.address>0x8001C780:
        break

# Check shim longjmp in w2kshim64.dll  
shim=pefile.PE("build_univ258/w2kshim64.dll")
# find longjmp export
for exp in shim.DIRECTORY_ENTRY_EXPORT.symbols:
  if exp.name and b'longjmp' == exp.name:
    print('longjmp rva', hex(exp.address))
    for i in md.disasm(shim.get_data(exp.address, 0x60), exp.address):
      print(f"  {i.address:04X}: {i.mnemonic} {i.op_str}")
