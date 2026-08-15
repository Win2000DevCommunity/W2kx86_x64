import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
pe = pefile.PE("build_univ258/cmd_probe_wfs.exe")
md = Cs(CS_ARCH_X86, CS_MODE_64)
print("=== 45980-45A20 ===")
for i in md.disasm(pe.get_data(0x45980, 0xA0), 0x80045980):
    print(f"  {i.address-0x80000000:06X}: {i.mnemonic} {i.op_str}")

# Search for pattern of corrupt jcc: 6683f8xx 0f00
text = pe.get_data(0x1000, 0x57000)
hits=[]
for off in range(len(text)-10):
    if text[off:off+3]==bytes.fromhex("6683f8") and text[off+4:off+6]==bytes.fromhex("0f00"):
        hits.append(off+0x1000)
    if text[off:off+2]==bytes.fromhex("0f00") and off>4:
        # preceded by cmp ax?
        if text[off-4:off]==bytes.fromhex("6683f840") or text[off-4:off]==bytes.fromhex("6683f828"):
            hits.append(off+0x1000)
print("corrupt hits", [hex(h) for h in hits])

# Also 0f84/0f85 with zero rel that became 0f00?
