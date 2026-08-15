import ctypes as C, struct, sys, os
sys.path.insert(0, ".")
import dbg_fault as df
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
k32=C.WinDLL("kernel32", use_last_error=True)
df.suppress_fault_ui()
os.chdir("build_univ230")
exe=os.path.abspath("cmd_fix8.exe")
IB=0x80000000
# before call d08c and at d9bc entry
NAMES={
 IB+0xc590:"before_d08c",  # need find call
 IB+0xd08c:"d08c_entry",
 IB+0xd9bc:"early_ret",
}
# find call to d08c from c514
pe=open(exe,"rb").read()
e=struct.unpack_from("<I",pe,0x3C)[0]
ns=struct.unpack_from("<H",pe,e+6)[0]; so=struct.unpack_from("<H",pe,e+20)[0]; sec=e+24+so
for i in range(ns):
    o=sec+i*40
    if pe[o:o+5]==b".text":
        vs,va,rs,rp=struct.unpack_from("<IIII",pe,o+8); break
md=Cs(CS_ARCH_X86,CS_MODE_64)
print("==== c514 area ====")
for insn in md.disasm(pe[rp+(0xc514-va):rp+(0xc5c0-va)], IB+0xc514):
    print(f"  {insn.address:#x}: {insn.mnemonic} {insn.op_str}")

print("==== near d9bc stack ops ====")
for insn in md.disasm(pe[rp+(0xd900-va):rp+(0xd9d0-va)], IB+0xd900):
    print(f"  {insn.address:#x}: {insn.mnemonic} {insn.op_str}")
