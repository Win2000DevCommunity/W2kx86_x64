import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
pe = pefile.PE("build_univ256/cmd_probe_pushrcx.exe")
md = Cs(CS_ARCH_X86, CS_MODE_64)
base = 0x80000000
print("--- 18E30-18E90 ---")
for i in md.disasm(pe.get_data(0x18E30, 0x60), base+0x18E30):
    print(f"  {i.address-base:06X}: {i.bytes.hex():28s} {i.mnemonic} {i.op_str}")
print("--- prologue path / sub rsp ---")
for i in md.disasm(pe.get_data(0x189C4, 0x80), base+0x189C4):
    print(f"  {i.address-base:06X}: {i.mnemonic} {i.op_str}")
# find jmp from sub
data=pe.get_data(0x189C4, 0x200)
idx=data.find(bytes.fromhex('e9'))
# find 4881ec or e9 near start after homes
print("--- search sub/push r12 ---")
text=pe.get_data(0x1000,0x57000)
# find cave with sub rsp 210 + push r12
pat=bytes.fromhex('4881ec100200004154')
j=0
while True:
    k=text.find(pat,j)
    if k<0: break
    print(f"pro cave at {k+0x1000:#x}")
    j=k+1
pat=bytes.fromhex('5f5e5b415cc9c3')
j=0
while True:
    k=text.find(pat,j)
    if k<0: break
    print(f"epi cave at {k+0x1000:#x}")
    j=k+1
