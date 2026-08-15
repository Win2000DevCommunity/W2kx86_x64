import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
pe = pefile.PE("build_univ256/cmd_probe_pushrcx.exe")
md = Cs(CS_ARCH_X86, CS_MODE_64); md.detail=True
base = 0x80000000
print("=== full 4276C until padding ===")
count=0
for i in md.disasm(pe.get_data(0x4276C, 0x400), base+0x4276C):
    mark=""
    if "rbp" in i.op_str or i.mnemonic in ("leave","enter") or i.bytes[0] in (0x55,0x5d):
        mark=" <<<"
    print(f"  {i.address-base:06X}: {i.bytes.hex():28s} {i.mnemonic} {i.op_str}{mark}")
    count+=1
    if i.mnemonic=="ret" and count>10:
        # continue a bit more for multiple rets
        if count>80:
            break
