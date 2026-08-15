import struct, pathlib
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
md=Cs(CS_ARCH_X86, CS_MODE_64)
pe=pathlib.Path("build_univ238/cmd_probe2.exe").read_bytes()
e=struct.unpack_from("<I",pe,0x3C)[0]
ns=struct.unpack_from("<H",pe,e+6)[0]; so=struct.unpack_from("<H",pe,e+20)[0]; sec=e+24+so
for i in range(ns):
    o=sec+i*40
    if pe[o:o+5]==b".text":
        vs,va,rs,rp=struct.unpack_from("<IIII",pe,o+8); break
print("==== and trampoline 37bae ====")
o=rp+(0x37bae-va)
print(pe[o:o+20].hex())
for insn in md.disasm(pe[o:o+0x20], 0x80000000+0x37bae):
    print(f"  {insn.address:#x}: {insn.mnemonic} {insn.op_str}")
# also check if and was left broken at original site
print("\nx86 terminator path around 18fa8")
# What does original cmd_pure look like at and site before trampoline?
# dump all 66 81 and rbp forms
sig=bytes.fromhex("6681a5")
i=rp; hits=[]
while True:
    j=pe.find(sig,i,rp+rs)
    if j<0: break
    hits.append(va+j-rp); i=j+1
print("and word [rbp+disp]", [hex(h) for h in hits[:10]])
sig2=bytes.fromhex("668124")  # and word [SIB]
i=rp; hits=[]
while True:
    j=pe.find(sig2,i,rp+rs)
    if j<0: break
    hits.append(va+j-rp); i=j+1
print("and word [sib]", [hex(h) for h in hits[:10]])
