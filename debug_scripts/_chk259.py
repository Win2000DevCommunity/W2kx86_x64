import pefile, struct
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
pe = pefile.PE("build_univ259/cmd_pure.exe")
md = Cs(CS_ARCH_X86, CS_MODE_64)
# waiter fae0==0 path
print("=== waiter ~45820 ===")
# find cmp [fae0],0 then wait
text = pe.sections[0].get_data(); base = pe.sections[0].VirtualAddress
# search movabs r11, ...bae0; cmp dword [r11],0
sig = bytes.fromhex("41833b000f85")  # cmp dword [r11],0; jne
hits=[]
i=0
while True:
    j=text.find(sig,i)
    if j<0: break
    # look back for bae0 in imm
    window=text[max(0,j-20):j]
    if b'\xe0\xba' in window or b'\xe0\xba\x05' in window:
        hits.append(base+j)
    i=j+1
print("fae0==0 sites", [hex(h) for h in hits[:10]])
for h in hits[:3]:
    print(f"\n--- {h:06X} ---")
    for insn in md.disasm(pe.get_data(h-30, 0x50), 0x80000000+h-30):
        print(f"  {insn.address-0x80000000:06X}: {insn.mnemonic} {insn.op_str}")
        if insn.address > 0x80000000+h+0x30: break

# setjmp bb40 site
pat=struct.pack('<Q', 0x8005bb40)
offs=[]; i=0
while True:
    j=text.find(pat,i)
    if j<0: break
    offs.append(base+j); i=j+1
print("\n5bb40 refs", [hex(o) for o in offs[:12]])
