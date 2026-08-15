from pathlib import Path
import struct
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
import w2kseh64

fresh = w2kseh64.build_longjmp()
print("fresh longjmp len", len(fresh), fresh.hex())
md = Cs(CS_ARCH_X86, CS_MODE_64)
print("fresh disasm:")
for insn in md.disasm(fresh, 0):
    print(f"  {insn.address:#04x}  {insn.mnemonic} {insn.op_str}")

# Find longjmp in shim dll
dll = Path("build_univ13/w2kshim64.dll").read_bytes()
# search for unique sequence from build_longjmp start: mov [rcx], rbp = 48 89 29?
# JB_RBP store: 48 89 29 at start of setjmp; longjmp loads 48 8B 29
sig = bytes.fromhex("488b29488b5908488b7948")  # mov rbp,[rcx]; mov rbx,[rcx+8]; mov rdi,[rcx+10]?
# actually check encoding
print("\nsearch fresh prefix in dll", dll.find(fresh[:16]))
idx = dll.find(fresh[:20])
print("full20 at", idx)
if idx < 0:
    # try without the new guard - old pattern
    old_tail = bytes.fromhex("85d27502ba0100000089d04152c3")
    print("old tail at", dll.find(old_tail))
    new_guard = bytes.fromhex("4d85d2")
    print("test r10,r10 count", dll.count(new_guard))
