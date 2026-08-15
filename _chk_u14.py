from pathlib import Path
from tools.audit_calls import read_text_section
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
trva,data,_=read_text_section(Path("build_univ14/cmd_pure.exe").read_bytes())
md=Cs(CS_ARCH_X86, CS_MODE_64)
print("=== setjmp fb40 site ===")
# search movabs rcx, 0x80060b40
import struct
pat=struct.pack("<Q", 0x80060b40)
i=data.find(pat)
print("first fb40 at", hex(trva+i))
for insn in md.disasm(data[max(0,i-20):i+40], trva+max(0,i-20), count=15):
    print(f"  {insn.address:#07x}  {insn.bytes.hex():28s} {insn.mnemonic} {insn.op_str}")
print("\nlongjmp rip load in shim:")
from capstone import Cs
import w2kseh64
dll=Path("build_univ14/w2kshim64.dll").read_bytes()
fresh=w2kseh64.build_longjmp()
print("shim has r10 load", b"\x4c\x8b\x51\x28" in dll)
