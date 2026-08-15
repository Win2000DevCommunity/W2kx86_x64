import pefile, struct
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
pe = pefile.PE("build_univ258/cmd_probe_jcc.exe")
md = Cs(CS_ARCH_X86, CS_MODE_64)
print("=== waiter 45820 ===")
for i in md.disasm(pe.get_data(0x45820, 0x50), 0x80045820):
    print(f"  {i.address-0x80000000:06X}: {i.mnemonic} {i.op_str}")

# count WFS vs longjmp abs imm in text
text=pe.sections[0].get_data()
wfs=struct.pack('<Q',0x800845f0)
lj=struct.pack('<Q',0x80084e78)
print('WFS imm count', text.count(wfs), 'longjmp imm', text.count(lj))
