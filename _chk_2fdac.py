from pathlib import Path
from tools.audit_calls import read_text_section
from x86x64.translator._analysis import AnalysisMixin
from x86x64.translator._healing import HealingMixin
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
import struct
trva,data,_=read_text_section(Path("build_univ9/cmd_pure.exe").read_bytes())
md=Cs(CS_ARCH_X86, CS_MODE_64)
b=bytearray(data)
for a in (0x2fda4,0x2fda8,0x2fdac,0x2fdb0,0x2fdb6):
    print(hex(a), "prologue", AnalysisMixin._x64_entry_prologue_ok(data,a-trva),
          "midimm", HealingMixin._pure_off_in_movabs_imm(b,a-trva),
          "bytes", data[a-trva:a-trva+8].hex())
print("---")
for ins in md.disasm(data[0x2fd90-trva:0x2fde0-trva], 0x2fd90):
    print(hex(ins.address), ins.bytes.hex(), ins.mnemonic, ins.op_str)
