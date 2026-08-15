# count how many jcc land on nop;ret vs mov eax,esi; pop rsi; ret near 386xx
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
import struct, pathlib
pe = bytearray(pathlib.Path("build_univ227/cmd_echo2.exe").read_bytes())
e = struct.unpack_from("<I", pe, 0x3C)[0]
ns = struct.unpack_from("<H", pe, e+6)[0]
so = struct.unpack_from("<H", pe, e+20)[0]
sec = e+24+so
for i in range(ns):
    o = sec+i*40
    if pe[o:o+5] == b".text":
        vs,va,rs,rp = struct.unpack_from("<IIII", pe, o+8); break
code = bytearray(pe[rp:rp+rs])
good = bytes.fromhex("89f05ec3")  # mov eax,esi; pop rsi; ret
bare = []
for i in range(len(code)-6):
    if code[i]==0x0F and code[i+1] in (0x84,0x85,0x8C,0x8D,0x8E,0x8F,0x82,0x83):
        rel=struct.unpack_from("<i",code,i+2)[0]
        tgt=i+6+rel
        if 0<=tgt<len(code) and code[tgt]==0x90 and code[tgt+1]==0xC3:
            # look nearby for good epi
            near=None
            for d in range(-8, 16):
                if 0<=tgt+d<=len(code)-4 and code[tgt+d:tgt+d+4]==good:
                    near=tgt+d; break
            bare.append((va+i, va+tgt, va+near if near else None))
print("jcc->nop;ret count", len(bare))
for a,b,c in bare[:30]:
    print(hex(a),"->",hex(b),"near good",hex(c) if c else None)

# quick patch 19f72 jne to 386b1 and smoke
struct.pack_into("<i", code, 0x19f72-va+2, 0x386b1 - (0x19f72+6))
pe[rp:rp+rs]=code
pathlib.Path("build_univ227/cmd_epi.exe").write_bytes(pe)
