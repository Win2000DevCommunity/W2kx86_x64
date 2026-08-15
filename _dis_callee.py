import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
pe = pefile.PE("build_univ256/cmd_probe_pushrcx.exe")
md = Cs(CS_ARCH_X86, CS_MODE_64)
base = 0x80000000

def dis(rva, n=120):
    data = pe.get_data(rva, n)
    print("bytes", data[:32].hex())
    for i in md.disasm(data, base + rva):
        print(f"  {i.address-base:06X}: {i.bytes.hex():28s} {i.mnemonic} {i.op_str}")

print("=== callee 4276C ===")
dis(0x4276C, 80)
print("=== 37E6D ===")
dis(0x37E60, 40)
# what section is 4276c?
for s in pe.sections:
    va, vsz = s.VirtualAddress, s.Misc_VirtualSize
    if va <= 0x4276C < va + vsz:
        print("4276c in", s.Name, hex(va), hex(vsz), "chars", pe.get_data(0x4276C, 40))
    if va <= 0x37E6D < va + vsz:
        print("37e6d in", s.Name, hex(va), "data", pe.get_data(0x37E6D, 20))
