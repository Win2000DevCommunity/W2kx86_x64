from pathlib import Path
from tools.audit_calls import read_text_section
import struct
trva,data,_=read_text_section(Path("build_univ11/cmd_pure.exe").read_bytes())
for i in range(0x49a80-trva, 0x49aa0-trva):
    if data[i]==0xe8 and bytes(data[i-4:i])==bytes.fromhex("4883e4f0"):
        t=(trva+i+5+struct.unpack_from("<i",data,i+1)[0])&0xffffffff
        print("inner", hex(trva+i), "->", hex(t), data[t-trva:t-trva+4].hex())
