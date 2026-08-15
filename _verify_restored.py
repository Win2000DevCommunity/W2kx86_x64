"""Verify build 362: poll-loop stubs restored + global self-call census."""
import struct
import sys
import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

BUILD = sys.argv[1] if len(sys.argv) > 1 else 'build_univ362'
pe = pefile.PE(f'{BUILD}/cmd_pure.exe')
text = next(s for s in pe.sections if b'.text' in s.Name)
d = text.get_data()
base = pe.OPTIONAL_HEADER.ImageBase
va = base + text.VirtualAddress

pro = bytes.fromhex('41554989e54883ec204883e4f0')
epi = bytes.fromhex('4c89ec415d')
NEUT = b'\xB8\x00\x00\x01\x00'

def stub_at(p):
    if p + 18 > len(d):
        return None
    if d[p:p + 13] != pro:
        return None
    j = p + 13
    if d[j + 5:j + 10] != epi:
        return None
    if d[j] == 0xE8:
        return j + 5 + struct.unpack_from('<i', d, j + 1)[0]
    if d[j:j + 5] == NEUT:
        return None
    return -2

# Poll-loop stubs (x64 RVAs in the live 0xC4A8 chunk)
for rva, expect_name in ((0x4D44D, '0x14FE4 -> 0x59A6C'),
                         (0x4D4BB, '0xAC4F -> 0x1474C'),
                         (0x4D4E3, '0xEF42 -> 0x50710'),
                         (0x4D519, '0xAC92 -> 0x14828'),
                         (0x4D535, '0xAC4F -> 0x1474C'),
                         (0x4D645, '0xC814 -> 0x4D774'),
                         (0x4D65C, '0x14E07 -> ?')):
    tgt = stub_at(rva - va)
    print(f'stub 0x{rva:X}: tgt={hex(va + tgt) if tgt and tgt > 0 else tgt}  '
          f'({expect_name})')

# Global census
neutral = 0
selfcalls = 0
ok = 0
weird = 0
p = 0
while p < len(d) - 18:
    if d[p:p + 13] != pro:
        p += 1
        continue
    j = p + 13
    if j + 10 > len(d):
        break
    if d[j + 5:j + 10] != epi:
        p += 1
        continue
    if d[j:j + 5] == NEUT:
        neutral += 1
    elif d[j] == 0xE8:
        tgt = j + 5 + struct.unpack_from('<i', d, j + 1)[0]
        if tgt == p:
            selfcalls += 1
        else:
            ok += 1
    else:
        weird += 1
    p = j + 10
print(f'census: ok={ok} neutralized={neutral} self-calls={selfcalls} weird={weird}')
