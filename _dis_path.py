import pefile, struct
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
pe = pefile.PE("build_univ256/cmd_probe_pushrcx.exe")
md = Cs(CS_ARCH_X86, CS_MODE_64)
base = 0x80000000

def dis(rva, n=100):
    for i in md.disasm(pe.get_data(rva, n), base + rva):
        print(f"  {i.address-base:06X}: {i.bytes.hex():28s} {i.mnemonic} {i.op_str}")

print("=== around 37E60 ===")
dis(0x37E40, 0x50)
print("=== path builder 189C4-18F00 (sample) ===")
# find leave/ret and r12 parks in path area
data = pe.get_data(0x189C4, 0x600)
for i in md.disasm(data, base + 0x189C4):
    if i.mnemonic in ("leave", "ret", "call") or "r12" in i.op_str or "0xfffffffc" in i.op_str or i.mnemonic == "movabs":
        if "fffffffc" in i.op_str or i.address - base in range(0x18b00, 0x18f00) or "r12" in i.op_str:
            print(f"  {i.address-base:06X}: {i.mnemonic} {i.op_str}")

print("--- full 18B80-18EC0 ---")
dis(0x18B80, 0x150)
