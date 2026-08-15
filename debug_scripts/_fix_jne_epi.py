import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
pe = pefile.PE("build_univ258/cmd_probe_lj.exe")
md=Cs(CS_ARCH_X86,CS_MODE_64)
print("=== 474F0 ===")
for i in md.disasm(pe.get_data(0x474E8, 0x30), 0x800474E8):
    print(f"  {i.address-0x80000000:06X}: {i.mnemonic} {i.op_str}")

# Offline fix: change jne 474fc to jne 1C780-but that does mov eax,esi
# Better: materialize efd0 as pop rsi; pop rbx; pop rbp; ret at end of function
# Or retarget jne to 1C780+1 = 1C780 is mov eax,esi - use 1C780 and accept eax=esi?
# Correct: patch 1C67B jne to point to a cave: pop rsi; pop rbx; pop rbp; ret

# Also fix: after longjmp return value - use movsxd or ensure -1
# And check: does jne 474fc actually get taken? BP on 474fc

print("\nWho calls 1C5F8?")
text=pe.sections[0].get_data(); base=0x1000
import struct
target=0x1C5F8
hits=[]
for i in range(len(text)-5):
  if text[i]==0xE8:
    rel=struct.unpack_from('<i',text,i+1)[0]
    if i+5+rel==target-base:
      hits.append(base+i)
print([hex(h) for h in hits])
