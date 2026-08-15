import pefile, struct
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
pe = pefile.PE("build_univ257/cmd_pure.exe")
md = Cs(CS_ARCH_X86, CS_MODE_64)
# find call [WaitForSingleObject] via IAT 0x845f0
text = pe.get_data(0x1000, 0x57000)
iat = struct.pack("<Q", 0x800845F0)
idx=0
hits=[]
while True:
    p=text.find(iat, idx)
    if p<0: break
    hits.append(p+0x1000)
    idx=p+1
print("IAT refs", [hex(h) for h in hits])
for h in hits:
    print(f"\n=== {h:#x} ===")
    for i in md.disasm(pe.get_data(h-0x30, 0x60), 0x80000000+h-0x30):
        print(f"  {i.address-0x80000000:06X}: {i.mnemonic} {i.op_str}")
