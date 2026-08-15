import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
pe = pefile.PE("build_univ258/cmd_probe_jcc.exe")
md=Cs(CS_ARCH_X86,CS_MODE_64)
# full waiter from fae0 check
print("=== 457F0-45890 ===")
for i in md.disasm(pe.get_data(0x457F0, 0xA0), 0x800457F0):
    print(f"  {i.address-0x80000000:06X}: {i.mnemonic} {i.op_str}")

# What is event at 5bb40 - and does WFS get called?
# Also check if fae0 is seeded to 4000 in data
import struct
data_rva=None
for s in pe.sections:
  if s.Name.startswith(b'.data'):
    data_rva=s.VirtualAddress
    raw=s.get_data()
    # fae0 pe64 = 5bae0, offset in .data = 5bae0 - data_rva
    off=0x5bae0 - data_rva
    print('data va', hex(data_rva), 'fae0 off', hex(off), 'value', struct.unpack_from('<I', raw, off)[0] if 0<=off<len(raw) else 'oob')
