import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
pe = pefile.PE("build_univ257/cmd_pure.exe")
md = Cs(CS_ARCH_X86, CS_MODE_64)
# fae0 is at 0x5BAE0 - look for refs near 0x1Dxxx (from earlier disasm)
# search rip-rel loads of 0x5BAE0
import struct
text = pe.get_data(0x1000, 0x57000)
hits = []
for off in range(len(text)-7):
    # 8B 05 xx xx xx xx = mov eax,[rip+rel]
    # 83 3D xx xx xx xx 00 = cmp dword [rip+rel],0
    if text[off] == 0x83 and text[off+1] == 0x3D and text[off+6] == 0:
        rel = struct.unpack_from("<i", text, off+2)[0]
        tgt = (off + 0x1000 + 7 + rel) & 0xffffffff
        if tgt == 0x5BAE0:
            hits.append(off+0x1000)
    if text[off] == 0x8B and text[off+1] == 0x05:
        rel = struct.unpack_from("<i", text, off+2)[0]
        tgt = (off + 0x1000 + 6 + rel) & 0xffffffff
        if tgt == 0x5BAE0:
            hits.append(off+0x1000)
print("fae0 refs", [hex(h) for h in hits])
for h in hits[:5]:
    print(f"\n=== around {h:#x} ===")
    for i in md.disasm(pe.get_data(h-0x20, 0x80), 0x80000000+h-0x20):
        m = " <<<" if i.address-0x80000000==h else ""
        print(f"  {i.address-0x80000000:06X}: {i.mnemonic} {i.op_str}{m}")
