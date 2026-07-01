import pefile, struct, capstone, sys

SRC = r"C:\Users\win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU\cmd.exe"
TARGET = int(sys.argv[1], 16) if len(sys.argv) > 1 else 0x4ad1cf64

spe = pefile.PE(SRC)
ib = spe.OPTIONAL_HEADER.ImageBase
needle = struct.pack('<I', TARGET)
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
for s in spe.sections:
    if not s.Name.startswith(b'.text'):
        continue
    data = s.get_data()
    base = s.VirtualAddress
    i = 0
    hits = []
    while True:
        j = data.find(needle, i)
        if j < 0:
            break
        hits.append(j)
        i = j + 1
    print(f"refs to {hex(TARGET)}: {len(hits)}")
    for j in hits:
        # disassemble a 16-byte window starting a bit before to catch the instr
        for back in range(0, 10):
            start = j - back
            for ins in md.disasm(data[start:start + 12], ib + base + start):
                if ins.address <= ib + base + j < ins.address + ins.size:
                    print(f"  {hex(ins.address - ib)}: {ins.mnemonic} {ins.op_str}")
                break
            else:
                continue
            break
