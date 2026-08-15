from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from tools.audit_calls import read_text_section
from pathlib import Path

trva, data, _ = read_text_section(Path("build_envfix2/cmd_pure.exe").read_bytes())
md = Cs(CS_ARCH_X86, CS_MODE_64)
print("=== full 0x9e70 ===")
for ins in md.disasm(data[0x9e70-trva:0x9e70-trva+0x120], 0x9e70):
    print("%#07x  %-20s %s %s" % (ins.address, ins.bytes.hex(), ins.mnemonic, ins.op_str))
    if ins.mnemonic in ("ret", "retn") and ins.address > 0x9e80:
        break
