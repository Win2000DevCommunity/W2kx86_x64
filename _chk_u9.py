from pathlib import Path
from tools.audit_calls import read_text_section, load_map
import struct
trva,data,_=read_text_section(Path("build_univ9/cmd_pure.exe").read_bytes())
# caller to 0xa4e7 region
for i in range(0x11800-trva, 0x11900-trva):
    if data[i]==0xe8 and bytes(data[i-4:i])==bytes.fromhex("4883e4f0"):
        t=(trva+i+5+struct.unpack_from("<i",data,i+1)[0])&0xffffffff
        if 0x49000 < t < 0x4a000:
            print("caller", hex(trva+i), "->", hex(t), "bytes", data[t-trva:t-trva+7].hex())
# opening
pat=bytes.fromhex("48c7c064240000")
h=trva+data.rfind(pat)
print("opening", hex(h))
