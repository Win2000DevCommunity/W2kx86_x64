from pathlib import Path
from tools.audit_calls import read_text_section, load_map
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
trva,data,_=read_text_section(Path("build_univ3/cmd_pure.exe").read_bytes())
rmap=load_map(Path("build_univ3/rva.txt"))
print("0xa4e7 ->", hex(rmap.get(0xa4e7)))
md=Cs(CS_ARCH_X86, CS_MODE_64)
start=rmap.get(0xa4e7, 0x49a00)
for ins in md.disasm(data[start-trva:start-trva+0x90], start, count=40):
    print(hex(ins.address), ins.bytes.hex(), ins.mnemonic, ins.op_str)
