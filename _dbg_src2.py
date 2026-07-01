import capstone, pefile

src = r"C:\Users\win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU\cmd.exe"
pe = pefile.PE(src)
ib = pe.OPTIONAL_HEADER.ImageBase
print("imagebase", hex(ib))
sec = None
for s in pe.sections:
    va = s.VirtualAddress
    vs = max(s.Misc_VirtualSize, s.SizeOfRawData)
    if va <= 0x14EB8 < va + vs:
        data = s.get_data()
        sec = s
        print("section", s.Name, hex(va))
        break
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
start_rva = 0x14E80
off = start_rva - sec.VirtualAddress
code = data[off:off + 0x60]
for ins in md.disasm(code, ib + start_rva):
    print(hex(ins.address - ib), ins.mnemonic, ins.op_str, ins.bytes.hex())
