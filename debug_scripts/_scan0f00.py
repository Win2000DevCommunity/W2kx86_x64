import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_MODE_32
pe = pefile.PE("build_univ258/cmd_probe_wfs.exe")
md = Cs(CS_ARCH_X86, CS_MODE_64)
print("=== pe64 45A9D (second wait) ===")
for i in md.disasm(pe.get_data(0x45A9D, 0x40), 0x80045A9D):
    print(f"  {i.address-0x80000000:06X}: {i.mnemonic} {i.op_str}  [{i.bytes.hex()}]")

# scan all 0F 00 after cmp patterns in .text
text = pe.sections[0].get_data()
base = pe.sections[0].VirtualAddress
hits=[]
for i in range(len(text)-10):
    # 66 83 F8 xx 0F 00  OR 83 F8 xx 0F 00 OR 83 F9/FA/FB
    if text[i]==0x0F and text[i+1]==0x00:
        # look back for cmp
        pre = text[max(0,i-8):i]
        hits.append((base+i, pre.hex(), text[i:i+6].hex()))
print('0F00 count', len(hits))
for h in hits[:30]:
    print(f"  {h[0]:06X} pre={h[1]}  jcc={h[2]}")
