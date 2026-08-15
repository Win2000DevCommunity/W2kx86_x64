import pefile, struct
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
pe = pefile.PE("build_univ258/cmd_probe_jcc.exe")
text = pe.sections[0].get_data()
base = pe.sections[0].VirtualAddress
# find E8 rel32 targeting 1D574
target = 0x1D574
hits=[]
for i in range(len(text)-5):
    if text[i]==0xE8:
        rel=struct.unpack_from('<i', text, i+1)[0]
        if i+5+rel == target - base:
            hits.append(base+i)
    if text[i]==0xE9:
        rel=struct.unpack_from('<i', text, i+1)[0]
        if i+5+rel == target - base:
            hits.append(base+i)
print('call/jmp to 1D574', [hex(h) for h in hits[:40]], 'count', len(hits))

# also to 1E62C
target=0x1E62C
hits=[]
for i in range(len(text)-5):
    if text[i]==0xE8:
        rel=struct.unpack_from('<i', text, i+1)[0]
        if i+5+rel == target - base:
            hits.append(base+i)
print('call to 1E62C', [hex(h) for h in hits[:40]], 'count', len(hits))

# disasm a few callers of 1E62C
md=Cs(CS_ARCH_X86,CS_MODE_64)
for h in hits[:8]:
    print(f'\ncaller {h:06X}:')
    for i in md.disasm(pe.get_data(h-20, 40), 0x80000000+h-20):
        print(f"  {i.address-0x80000000:06X}: {i.mnemonic} {i.op_str}")
