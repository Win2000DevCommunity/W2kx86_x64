from pathlib import Path
from tools.audit_calls import read_text_section
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

for name in ["build_univ12/cmd_pure.exe", "build_univ12/cmd_pure_healed.exe"]:
    trva, data, _ = read_text_section(Path(name).read_bytes())
    n = 0
    sites = []
    for i in range(len(data) - 5):
        if data[i] == 0xE9 and data[i+1:i+5] == b"\xfb\xff\xff\xff":
            n += 1
            sites.append(trva + i)
    print(name, "selfjmps", n, [hex(s) for s in sites], "trva", hex(trva))
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    print(" around 7700:")
    for insn in md.disasm(data[0x7700 - trva:0x7740 - trva], 0x7700, count=10):
        print(f"  {insn.address:#07x}  {insn.bytes.hex():28s} {insn.mnemonic} {insn.op_str}")
