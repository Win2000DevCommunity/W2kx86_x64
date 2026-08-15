from pathlib import Path
from tools.audit_calls import read_text_section, load_map
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
trva,data,_=read_text_section(Path("build_univ7/cmd_pure.exe").read_bytes())
rmap=load_map(Path("build_univ7/rva.txt"))
md=Cs(CS_ARCH_X86, CS_MODE_64)
# find maps near 0x9f4c
near=sorted([(o,n) for o,n in rmap.items() if 0x9f40<=o<=0x9f60], key=lambda x:x[0])
print("maps", [(hex(o),hex(n)) for o,n in near])
# also function containing 0x9eba
print("0x9eba", hex(rmap.get(0x9eba,0)))
start=rmap.get(0x9f40) or rmap.get(0x9f47) or rmap.get(0x9eba)
# search for call to 0x49a18 region
for i in range(len(data)-5):
    if data[i]!=0xe8: continue
    t=(trva+i+5+int.from_bytes(data[i+1:i+5],"little",signed=True))&0xffffffff
    if 0x49a18 <= t <= 0x49a40:
        print("call to entry at", hex(trva+i), "->", hex(t))
        for ins in md.disasm(data[max(0,i-40):i+10], trva+max(0,i-40), count=20):
            print(f"  {ins.address:#07x}  {ins.mnemonic} {ins.op_str}")
        break
