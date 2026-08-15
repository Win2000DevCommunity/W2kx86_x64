#!/usr/bin/env python3
import struct
import pefile

pe = pefile.PE(r"..\win2000_x64\cmd_shim.exe", fast_load=True)
for off in [0x3ED60, 0x3EDE0, 0x3FDA0, 0x3FDE0, 0x15E19]:
    if off >= pe.sections[0].Misc_VirtualSize:
        continue
    s = pe.get_data(off, 20)
    if s[:4] != b"\xff\xff\xff\xff":
        print(f"scope@{off:#x}: BAD sentinel {s[:4].hex()}")
        continue
    b, e, f, h = struct.unpack("<4I", s[4:20])
    print(f"scope@{off:#x}: begin={b:#x} end={e:#x} filter={f:#x} handler={h:#x}")
