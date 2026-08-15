import struct, re, sys, os
from capstone import *

exe = sys.argv[1] if len(sys.argv) > 1 else os.environ.get('X64_EXE', r'build_univ381\cmd_pure.exe')
f = open(exe, 'rb').read()
e_lfanew = struct.unpack_from('<I', f, 0x3C)[0]
nsec = struct.unpack_from('<H', f, e_lfanew + 6)[0]
opt = e_lfanew + 24
sec = opt + struct.unpack_from('<H', f, e_lfanew + 20)[0]
for i in range(nsec):
    off = sec + i * 40
    name = f[off:off + 8].rstrip(b'\x00')
    vs, va, rs, ra = struct.unpack_from('<IIII', f, off + 8)
    if name == b'.text':
        text_va, text_ra, text_rs = va, ra, rs
blob = f[text_ra:text_ra + text_rs]

epi = b'\x4c\x89\xec\x41\x5d'
n = 0
for m in re.finditer(rb'\xe8', blob):
    p = m.start()
    if p + 5 > len(blob):
        break
    rel = struct.unpack_from('<i', blob, p + 1)[0]
    t = p + 5 + rel
    if not (0 <= t < len(blob) - 8):
        continue
    is_callreg = (blob[t:t + 3] == b'\x41\xff\xd7'
                  or blob[t:t + 2] in (b'\xff\xd0', b'\xff\xd3', b'\xff\xd6'))
    has_epi = (blob[t + 3:t + 8] == epi or blob[t + 3:t + 7] == epi)
    if is_callreg and has_epi:
        # scan forward for a prologue: push rbp; mov rbp,rsp or home or align-stub
        snap = None
        for d in range(8, 0x40):
            q = t + d
            if q + 5 > len(blob):
                break
            if blob[q:q + 4] == b'\x55\x48\x89\xe5':
                snap = q
                break
            if blob[q:q + 4] == b'\x48\x89\x4c\x24':
                snap = q
                break
            if blob[q:q + 3] == b'\x41\x55\x49':
                snap = q
                break
        n += 1
        print(f'x64 {text_va+p:#x} -> {text_va+t:#x} snap={text_va+snap:#x}' if snap else f'x64 {text_va+p:#x} -> {text_va+t:#x} snap=None')
print('total:', n)
