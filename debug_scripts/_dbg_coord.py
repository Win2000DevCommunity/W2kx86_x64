import struct
from pathlib import Path
data=Path("build_univ18/cmd_pure.exe").read_bytes()
e=struct.unpack_from("<I", data, 0x3c)[0]
soh=struct.unpack_from("<H", data, e+20)[0]; sec=e+24+soh
num=struct.unpack_from("<H", data, e+6)[0]
for i in range(num):
    o=sec+i*40
    if data[o:o+5]==b".text":
        vs,va,rs,rp=struct.unpack_from("<IIII", data, o+8)
        print("text va", hex(va), "rp", hex(rp))
        # bytes at rva 14d46 and at blob-off 14d46
        print("via rva:", data[rp+0x14d46-va:rp+0x14d46-va+8].hex())
        print("via off as if va0:", data[rp+0x14d46:rp+0x14d46+8].hex() if 0x14d46<rs else "oob")
        print("at 13d46:", data[rp+0x13d46:rp+0x13d46+8].hex())
        print("at 13d6c:", data[rp+0x13d6c:rp+0x13d6c+8].hex())
        print("placeholder search as blob off:")
        text=data[rp:rp+rs]
        # if rva_map uses PE RVA, placeholders in out during translate use same
        # After PE emit, out[i] is at RVA text_rva+i ONLY if no padding
        print("count ph in section", text.count(b"\x0f\x00\x00\x00\x00\x00"))
