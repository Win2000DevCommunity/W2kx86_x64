import pefile, capstone, sys

exe = sys.argv[1] if len(sys.argv) > 1 else r"build_out79\cmd_pure.exe"
start = int(sys.argv[2], 16) if len(sys.argv) > 2 else 0x18B0A
length = int(sys.argv[3], 16) if len(sys.argv) > 3 else 0xB0
pe = pefile.PE(exe)
ib = pe.OPTIONAL_HEADER.ImageBase
sec = None
for s in pe.sections:
    if s.VirtualAddress <= start < s.VirtualAddress + max(s.Misc_VirtualSize, s.SizeOfRawData):
        sec = s
        data = s.get_data()
        break
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
off = start - sec.VirtualAddress
for ins in md.disasm(data[off:off + length], ib + start):
    print(f"main+0x{ins.address-ib:X}: {ins.mnemonic} {ins.op_str}  [{ins.bytes.hex()}]")
