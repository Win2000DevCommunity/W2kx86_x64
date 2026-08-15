import struct
from pathlib import Path
from capstone import Cs, CS_ARCH_X86, CS_MODE_32

src = Path(r"C:\Users\win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU\cmd.exe").read_bytes()
e = struct.unpack_from("<I", src, 0x3c)[0]
num = struct.unpack_from("<H", src, e+6)[0]; soh = struct.unpack_from("<H", src, e+20)[0]; sec = e+24+soh
base = struct.unpack_from("<I", src, e+24+28)[0]
print("image base", hex(base))
secs = []
for i in range(num):
    o = sec+i*40
    name = src[o:o+8].split(b"\x00")[0].decode()
    va,vs,rs,rp = struct.unpack_from("<IIII", src, o+12)
    secs.append((name,va,vs,rs,rp))
    print(f"  {name:8} VA={va:#x} VS={vs:#x} RS={rs:#x} RP={rp:#x}")

needle = struct.pack("<I", 0x4ad1c8d8)
print("\nAll file offsets containing 0x4ad1c8d8:")
i = 0
while True:
    j = src.find(needle, i)
    if j < 0: break
    # which section?
    rva = None; sn="?"
    for name,va,vs,rs,rp in secs:
        if rp <= j < rp+rs:
            rva = va + (j-rp); sn=name; break
    # decode surrounding if text
    print(f"  file={j:#x} sec={sn} rva={rva and hex(rva)}  context={src[j-4:j+8].hex()}")
    if sn == ".text" and rva is not None:
        md = Cs(CS_ARCH_X86, CS_MODE_32)
        # walk back a few bytes for insn start
        text = None
        for name,va,vs,rs,rp in secs:
            if name==".text":
                text=src[rp:rp+rs]; text_rva=va; break
        off = rva - text_rva
        # try disasm from off-8 to off+8
        for start in range(max(0,off-8), off+1):
            try:
                insns = list(md.disasm(text[start:off+8], base+text_rva+start, count=3))
                if any(abs(x.address - (base+rva)) < 8 for x in insns):
                    for insn in insns:
                        print(f"    try@{start-off:+d}: {insn.address-base:#07x}  {insn.mnemonic} {insn.op_str}")
                    break
            except Exception:
                pass
    i = j+1

# Also check .data init content at c8d8
for name,va,vs,rs,rp in secs:
    if name==".data":
        off = 0xc8d8 - va
        if 0 <= off < rs:
            print(f"\n.data init at c8d8 file: {src[rp+off:rp+off+16].hex()}")
        else:
            print(f"\nc8d8 is BSS (beyond raw .data size rs={rs:#x}, va={va:#x}, off={off:#x})")
