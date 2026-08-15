import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_MODE_32
pe = pefile.PE("build_univ258/cmd_probe_jcc.exe")
md=Cs(CS_ARCH_X86,CS_MODE_64)
# all je/jne from 1E62C body that land outside
print("=== 1E62C external branches ===")
for i in md.disasm(pe.get_data(0x1E62C, 0x130), 0x8001E62C):
  if i.mnemonic.startswith('j') and i.mnemonic!='jmp':
    # parse target
    if i.op_str.startswith('0x'):
      tgt=int(i.op_str, 16)-0x80000000
      if not (0x1E62C <= tgt <= 0x1E750):
        print(f"  {i.address-0x80000000:06X}: {i.mnemonic} {i.op_str} -> OUT")
  if i.mnemonic=='jmp' and i.op_str.startswith('0x'):
    tgt=int(i.op_str,16)-0x80000000
    if not (0x1E62C <= tgt <= 0x1E750) and tgt != 0x3988E:
      print(f"  {i.address-0x80000000:06X}: {i.mnemonic} {i.op_str} -> OUT")

# x86 fdcc path
x86=pefile.PE(r"C:\Users\win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU\cmd.exe")
md32=Cs(CS_ARCH_X86,CS_MODE_32)
print("\n=== x86 FDCC ===")
for i in md32.disasm(x86.get_data(0xFDCC, 0x50), 0xFDCC):
  print(f"  {i.address:06X}: {i.mnemonic} {i.op_str}")
