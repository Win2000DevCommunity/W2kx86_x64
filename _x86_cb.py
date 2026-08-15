import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_MODE_32
pe = pefile.PE("build_univ258/cmd_probe_jcc.exe")
md=Cs(CS_ARCH_X86,CS_MODE_64)
print("=== 1E62C complete head ===")
for i in md.disasm(pe.get_data(0x1E62C, 0x30), 0x8001E62C):
    print(f"  {i.address-0x80000000:06X}: {i.mnemonic} {i.op_str}")

# x86 of Lex or similar - the function that has callback as 4th arg
# Search x86 for pattern: call [ebp+14h] early after prologue  
x86=pefile.PE(r"C:\Users\win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU\cmd.exe")
md32=Cs(CS_ARCH_X86,CS_MODE_32)
text=x86.sections[0].get_data(); base=0x1000
# FF 55 14 = call [ebp+14]
hits=[]
for i in range(len(text)-3):
  if text[i:i+3]==bytes.fromhex('ff5514'):
    hits.append(base+i)
print('call [ebp+14]', [hex(h) for h in hits[:20]])
for h in hits[:5]:
  print(f'\n--- {h:04X} ---')
  for i in md32.disasm(x86.get_data(h-0x30, 0x50), h-0x30):
    print(f"  {i.address:06X}: {i.mnemonic} {i.op_str}")
    if i.address>h+8: break
