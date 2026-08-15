from pathlib import Path
from tools.audit_calls import read_text_section
import struct
trva,data,_=read_text_section(Path("build_univ10/cmd_pure.exe").read_bytes())
for i in range(0x11800-trva, 0x11900-trva):
    if data[i]==0xe8 and bytes(data[i-4:i])==bytes.fromhex("4883e4f0"):
        t=(trva+i+5+struct.unpack_from("<i",data,i+1)[0])&0xffffffff
        if 0x49000 < t < 0x4a000:
            print("caller", hex(trva+i), "->", hex(t), data[t-trva:t-trva+7].hex())
# find call from 0x49a8f area
pat=bytes.fromhex("48c7c064240000")
ent=trva+data.rfind(pat)
print("entry", hex(ent))
for i in range(ent-trva, ent-trva+0x90):
    if data[i]==0xe8 and i>10 and bytes(data[i-4:i])==bytes.fromhex("4883e4f0"):
        t=(trva+i+5+struct.unpack_from("<i",data,i+1)[0])&0xffffffff
        print("inner call", hex(trva+i), "->", hex(t), data[t-trva:t-trva+4].hex())
