import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_32
x86=pefile.PE(r"C:\Users\win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU\cmd.exe")
md32=Cs(CS_ARCH_X86,CS_MODE_32)
# event at 4ad1fb40
sig=bytes.fromhex('ff35f0fad14a')  # push dword [fb40] - wrong
# push dword ptr [0x4ad1fb40] = FF 35 40 FB D1 4A
sig=bytes.fromhex('ff3540fbd14a')
text=x86.get_memory_mapped_image()
idx=0
hits=[]
while True:
  i=text.find(sig, idx)
  if i<0: break
  hits.append(i); idx=i+1
print('push [fb40]', [hex(h) for h in hits])
for h in hits:
  print(f'\n=== {h:04X} ===')
  for ins in md32.disasm(text[h-8:h+16], h-8):
    print(f"  {ins.address:06X}: {ins.mnemonic} {ins.op_str}")

# also 6A FF FF 35 = push -1; push [fb40]
sig2=bytes.fromhex('6affff3540fbd14a')
print('push-1 push[fb40]', text.find(sig2))
