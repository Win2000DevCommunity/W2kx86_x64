import struct, re, sys, os
from capstone import *

X86 = r'C:\Users\win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU\cmd.exe'
X64 = os.environ.get('X64_EXE', r'build_univ373\cmd_pure.exe')
RVA_TXT = os.environ.get('RVA_TXT', r'build_univ373\rva.txt')

def sects(path):
    f = open(path, 'rb').read()
    e_lfanew = struct.unpack_from('<I', f, 0x3C)[0]
    nsec = struct.unpack_from('<H', f, e_lfanew + 6)[0]
    opt = e_lfanew + 24
    sec = opt + struct.unpack_from('<H', f, e_lfanew + 20)[0]
    out = []
    for i in range(nsec):
        off = sec + i * 40
        name = f[off:off + 8].rstrip(b'\x00')
        vs, va, rs, ra = struct.unpack_from('<IIII', f, off + 8)
        out.append((name, va, vs, ra, rs))
    return f, out

f86, s86 = sects(X86)
f64, s64 = sects(X64)

def dis86(rva, n):
    for name, va, vs, ra, rs in s86:
        if va <= rva < va + vs:
            o = ra + (rva - va); break
    else:
        print('no sect'); return
    md = Cs(CS_ARCH_X86, CS_MODE_32); md.detail = True
    for ins in md.disasm(f86[o:o + n], rva):
        print(f'{ins.address:#x}: {ins.bytes.hex():<16} {ins.mnemonic} {ins.op_str}')

def dis64(rva, n):
    for name, va, vs, ra, rs in s64:
        if va <= rva < va + vs:
            o = ra + (rva - va); break
    else:
        print('no sect'); return
    md = Cs(CS_ARCH_X86, CS_MODE_64); md.detail = True
    for ins in md.disasm(f64[o:o + n], rva):
        print(f'{ins.address:#x}: {ins.bytes.hex():<20} {ins.mnemonic} {ins.op_str}')

cmd = sys.argv[1]
if cmd == 'find86':
    for name, va, vs, ra, rs in s86:
        if name == b'.text':
            blob = f86[ra:ra + rs]
    for m in re.finditer(rb'\x81\xec\x64\x24\x00\x00', blob):
        print('sub esp,0x2464 at x86', hex(va + m.start()))
elif cmd == 'dis86':
    dis86(int(sys.argv[2], 16), int(sys.argv[3], 16))
elif cmd == 'dis64':
    dis64(int(sys.argv[2], 16), int(sys.argv[3], 16))
elif cmd == 'map':
    lines = open(RVA_TXT).read().splitlines()
    lo, hi = int(sys.argv[2], 16), int(sys.argv[3], 16)
    for l in lines:
        p = l.split()
        x, y = int(p[0], 16), int(p[1], 16)
        if lo <= y <= hi:
            print(f'x86 {x:#x} -> x64 {y:#x}')
elif cmd == 'mapx':
    # map by x86 range: mapx <x86lo> <x86hi> [rvatxt]
    rvatxt = sys.argv[4] if len(sys.argv) > 4 else RVA_TXT
    lines = open(rvatxt).read().splitlines()
    lo, hi = int(sys.argv[2], 16), int(sys.argv[3], 16)
    for l in lines:
        p = l.split()
        x, y = int(p[0], 16), int(p[1], 16)
        if lo <= x <= hi:
            print(f'x86 {x:#x} -> x64 {y:#x}')
elif cmd == 'findcalls':
    # findcalls <x64lo> <x64hi>  : list E8/E9 whose TARGET is in [lo,hi)
    for name, va, vs, ra, rs in s64:
        if name == b'.text':
            text_va, text_ra, text_rs = va, ra, rs
    blob = f64[text_ra:text_ra + text_rs]
    lo, hi = int(sys.argv[2], 16), int(sys.argv[3], 16)
    import re as _re
    for op in (0xE8, 0xE9):
        for m in _re.finditer(bytes([op]), blob):
            pos = m.start()
            if pos + 5 > len(blob):
                break
            rel = struct.unpack_from('<i', blob, pos + 1)[0]
            t = (text_va + pos + 5 + rel) & 0xFFFFFFFF
            if lo <= t < hi:
                print(f'{"call" if op==0xE8 else "jmp "} at x64 {text_va+pos:#x} -> {t:#x}')
elif cmd == 'findfunc':
    # findfunc <x64addr> : walk back to enclosing function entry (after a ret/jmp tail)
    for name, va, vs, ra, rs in s64:
        if name == b'.text':
            text_va, text_ra, text_rs = va, ra, rs
    blob = f64[text_ra:text_ra + text_rs]
    t = int(sys.argv[2], 16)
    # simple: find nearest preceding C3 within 0x800, entry = after it
    start = max(0, (t - text_va) - 0x800)
    best = start
    for pos in range(start, (t - text_va)):
        if blob[pos] == 0xC3:
            best = pos + 1
        elif blob[pos] == 0xC2:
            best = pos + 3
    print(f'enclosing entry est: x64 {text_va + best:#x}')
elif cmd == 'xcallers':
    # xcallers <x86rva> : all x86 E8 sites whose target == rva
    import re as _re
    tgt = int(sys.argv[2], 16)
    for name, va, vs, ra, rs in s86:
        if name == b'.text':
            tva, tra, trs = va, ra, rs
    blob = f86[tra:tra + trs]
    for m in _re.finditer(b'\xe8', blob):
        p = m.start()
        if p + 5 > len(blob):
            break
        rel = struct.unpack_from('<i', blob, p + 1)[0]
        if (tva + p + 5 + rel) & 0xFFFFFFFF == tgt:
            print(f'x86 {tva+p:#x} calls {tgt:#x}')
elif cmd == 'fcallers':
    # fcallers <x64rva> : all E8 sites in final binary whose target == rva
    import re as _re
    tgt = int(sys.argv[2], 16)
    for name, va, vs, ra, rs in s64:
        if name == b'.text':
            tva, tra, trs = va, ra, rs
    blob = f64[tra:tra + trs]
    for m in _re.finditer(b'\xe8', blob):
        p = m.start()
        if p + 5 > len(blob):
            break
        rel = struct.unpack_from('<i', blob, p + 1)[0]
        if (tva + p + 5 + rel) & 0xFFFFFFFF == tgt:
            print(f'x64 {tva+p:#x} calls {tgt:#x}')
