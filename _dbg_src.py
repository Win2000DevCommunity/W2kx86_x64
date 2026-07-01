import capstone, pefile, sys

src = r"C:\Users\win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU\cmd.exe"
pe = pefile.PE(src)
ib = pe.OPTIONAL_HEADER.ImageBase
start_rva = int(sys.argv[1], 16) if len(sys.argv) > 1 else 0x14E80
length = int(sys.argv[2], 16) if len(sys.argv) > 2 else 0x60
sec = None
for s in pe.sections:
    if s.VirtualAddress <= start_rva < s.VirtualAddress + max(s.Misc_VirtualSize, s.SizeOfRawData):
        sec = s
        data = s.get_data()
        break
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
off = start_rva - sec.VirtualAddress
code = data[off:off + length]
for ins in md.disasm(code, ib + start_rva):
    print(hex(ins.address - ib), ins.mnemonic, ins.op_str, ins.bytes.hex())
