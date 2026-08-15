import struct
from pathlib import Path
from tools.audit_calls import read_text_section, load_map
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from x86x64.translator._analysis import AnalysisMixin

blob = Path("build_univ5/cmd_pure.exe").read_bytes()
trva, data, _ = read_text_section(blob)
rmap = load_map(Path("build_univ5/rva.txt"))
md = Cs(CS_ARCH_X86, CS_MODE_64)

print("0x195d2 ->", hex(rmap.get(0x195d2, 0)))
off = rmap.get(0x195d2)
if off:
    print("bytes", data[off-trva:off-trva+8].hex(),
          "prologue", AnalysisMixin._x64_entry_prologue_ok(data, off-trva))
    for ins in md.disasm(data[off-trva:off-trva+24], off, count=4):
        print(" ", hex(ins.address), ins.mnemonic, ins.op_str)

# Count calls into movabs immediates
mid = 0
to_195 = 0
bad_prologue = 0
for i in range(len(data)-5):
    if data[i] != 0xE8: continue
    t = (trva+i+5+struct.unpack_from("<i", data, i+1)[0]) & 0xffffffff
    to = t - trva
    if not (0 <= to < len(data)): continue
    # mid movabs?
    for back in range(2,10):
        p = to - back
        if p < 0: break
        if data[p] in (0x48,0x49,0x4c,0x4d) and 0xb8 <= data[p+1] <= 0xbf and p+2 <= to <= p+9:
            mid += 1
            break
    if off and t == off:
        to_195 += 1
    if 0 <= to < len(data) and not AnalysisMixin._x64_entry_prologue_ok(data, to):
        # only count real-looking calls (after align)
        if data[i-4:i] == bytes.fromhex("4883e4f0"):
            bad_prologue += 1

print("calls into movabs imm:", mid)
print("calls to 0x195d2 entry:", to_195)
print("align-stub calls to non-prologue:", bad_prologue)
