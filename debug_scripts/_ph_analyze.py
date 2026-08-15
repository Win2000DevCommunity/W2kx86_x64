import pefile, struct
from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64

pe = pefile.PE("build_univ258/cmd_probe_wfs.exe")
text = pe.sections[0].get_data()
base = pe.sections[0].VirtualAddress
ph = [base+i for i in range(len(text)-5) if text[i:i+6]==b'\x0f\x00\x00\x00\x00\x00']
print('exact placeholders', len(ph))
print('near 458B3', [hex(p) for p in ph if 0x45800<=p<=0x45b00])
print('sample first 20', [hex(p) for p in ph[:20]])

# Try to understand why f7b4 isn't patched - check if we can load rva from a dump
# Simulate: for placeholder at 458B3-0x1000? wait VA vs file offset
# .text VA is typically 0x1000, so blob offset = VA - 0x1000
print('text VA', hex(base))
off = 0x458B3 - base
print('blob off 458B3', hex(off), 'bytes', text[off:off+6].hex())
# preceding cmp
print('pre', text[off-4:off].hex())

# x86: f7b4 is jne. Tip might be on f7b0 cmp
x86 = pefile.PE(r"C:\Users\win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU\cmd.exe")
# Check nearby mapped tips - without rva_map we look at structural: 
# placeholder after cmp ax,imm should be jne to call 10005 body

# Pattern heal without full rva_map:
# 66 83 F8 xx / 83 F8 xx followed by 0F 00 00 00 00 00
# Look ahead for: call-like OR movabs starting 10005 pattern OR mov eax,esi; pop; ret then call body

def find_skip_targets(blob, ph_off):
    """After corrupt jne for skip-to-call-helper pattern, find call 10005-like or success+fail."""
    # scan forward up to 0x200 for 89 f0 5e c3 (mov eax,esi; pop rsi; ret) then next is fail path
    window = blob[ph_off:ph_off+0x200]
    for i in range(len(window)-4):
        if window[i:i+4]==bytes.fromhex('89f05ec3'):
            return ph_off+i+4  # fail path after success epi
    return None

for p in [0x458B3, 0x459C1]:
    o = p - base
    tgt = find_skip_targets(text, o)
    print(hex(p), 'suggested tgt', hex(tgt+base) if tgt else None, 'pre', text[o-4:o].hex())
