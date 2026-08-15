"""At longjmp call, the registers showed RCX=jmp_buf. RIP after longjmp was in ntdll.
Check: is saved RIP in-image? Was setjmp site reached?
Re-run with a breakpoint watch - simpler: read dbg and also check setjmp encoding stores RIP.
"""
from pathlib import Path
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
import w2kseh64

print("setjmp:")
for insn in Cs(CS_ARCH_X86, CS_MODE_64).disasm(w2kseh64.build_setjmp3(), 0):
    print(f"  {insn.address:#04x}  {insn.bytes.hex():20s} {insn.mnemonic} {insn.op_str}")

# From fault: RBP restored to 1, RIP went to system. Saved RIP was pushed.
# RBX=0x8001AE51 ? that was restored from jmp_buf JB_RBX.
# RSI=0x8001AE17 ? from JB_RSI  
# These look like CODE addresses near the setjmp return path (0x1ae04 area)!
print()
print("setjmp site was around 0x1adde; return ~0x1ae07")
print("RBX=0x8001AE51 RSI=0x8001AE17 ? look like scrambled saved regs from setjmp site")
print("RBP=1 ? wrong; RSP was 0x14FD90 after longjmp")

# Disasm setjmp caller epilogue region in univ13
from tools.audit_calls import read_text_section
trva,data,_=read_text_section(Path("build_univ13/cmd_pure.exe").read_bytes())
md=Cs(CS_ARCH_X86, CS_MODE_64)
print("\n=== setjmp fb40 caller ===")
for insn in md.disasm(data[0x1adc0-trva:0x1ae40-trva], 0x1adc0, count=30):
    print(f"  {insn.address:#07x}  {insn.mnemonic} {insn.op_str}")
