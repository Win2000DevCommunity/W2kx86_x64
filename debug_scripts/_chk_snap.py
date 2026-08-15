from pathlib import Path
from tools.audit_calls import read_text_section, load_map
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from x86x64.translator._analysis import AnalysisMixin

blob = Path("build_univ3/cmd_pure.exe").read_bytes()
trva, data, _ = read_text_section(blob)
data = bytearray(data)
md = Cs(CS_ARCH_X86, CS_MODE_64)

tgt = 0x31e85 - trva
# Simulate insn boundary snap for one call
i = 0x49ac3 - trva
rel = int.from_bytes(data[i+1:i+5], "little", signed=True)
print("call off", hex(i), "tgt", hex(i+5+rel), "trva-relative")

# Would snap find it?
scan_lo = max(0, tgt - 14)
snapped = None
for start in range(scan_lo, tgt + 1):
    insns = list(md.disasm(bytes(data[start:start+20]), start, count=8))
    for ins in insns:
        if ins.address > tgt: break
        end = ins.address + ins.size
        if ins.address <= tgt < end and ins.address != tgt:
            snapped = ins.address
            print("would snap", hex(snapped+trva), "from start", hex(start+trva), ins.mnemonic, ins.op_str)
            break
    if snapped is not None:
        break
print("snapped", None if snapped is None else hex(snapped+trva))

# Check if 0x31e85 is reachable as insn start from nearby
print("\nDisasm from 0x31e7d:")
for ins in md.disasm(bytes(data[0x31e7d-trva:0x31e90-trva]), 0x31e7d-trva):
    print(hex(ins.address+trva), ins.mnemonic, ins.op_str, "size", ins.size)

# Why would find_enclosing miss?
# Check mapped entries near
rmap = load_map(Path("build_univ3/rva.txt"))
entries = sorted({n for n in rmap.values() if 0x31e00 <= n <= 0x31f00})
print("mapped offs near:", [hex(e) for e in entries])
