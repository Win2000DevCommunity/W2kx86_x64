import struct, sys

path = sys.argv[1] if len(sys.argv) > 1 else r'build_univ383\cmd_pure.exe'
want_rva = int(sys.argv[2], 16) if len(sys.argv) > 2 else 0

f = open(path, 'rb').read()
e = struct.unpack_from('<I', f, 0x3C)[0]
nsec = struct.unpack_from('<H', f, e + 6)[0]
opt = e + 24
sec = opt + struct.unpack_from('<H', f, e + 20)[0]
sects = []
for i in range(nsec):
    off = sec + i * 40
    name = f[off:off + 8].rstrip(b'\x00')
    vs, va, rs, ra = struct.unpack_from('<IIII', f, off + 8)
    sects.append((name, va, vs, ra, rs))

def rva_to_off(rva):
    for name, va, vs, ra, rs in sects:
        if va <= rva < va + max(vs, rs):
            return ra + (rva - va)
    return None

od = e + 24 + 112
imp_rva = struct.unpack_from('<I', f, od + 8)[0]
print('import dir rva', hex(imp_rva))
off = rva_to_off(imp_rva)
for di in range(8):
    base = off + di * 20
    if base + 20 > len(f):
        break
    oft, ts, name_rva, ft_rva, ot_rva = struct.unpack_from('<IIIII', f, base)
    if oft == 0 and ts == 0:
        break
    no = rva_to_off(name_rva)
    dll = f[no:f.index(b'\x00', no)].decode('latin1') if no else '?'
    # walk ILT (orig thunk) for names
    to = rva_to_off(ot_rva or ft_rva)
    ents = []
    k = 0
    while to is not None and to + (k + 1) * 8 <= len(f):
        val = struct.unpack_from('<Q', f, to + k * 8)[0]
        if val == 0:
            break
        if val & 0x8000000000000000:
            ents.append((ot_rva + k * 8, val & 0xFFFF, '<ord>'))
        else:
            ho = rva_to_off(val & 0xFFFFFFFF)
            if ho is None:
                ents.append((ot_rva + k * 8, val, '?'))
            else:
                nm = f[ho + 2:f.index(b'\x00', ho + 2)].decode('latin1')
                ents.append((ot_rva + k * 8, val, nm))
        k += 1
    print(f'desc {di}: {dll} ft={ft_rva:#x} ot={ot_rva:#x}')
    for slot_rva, val, nm in ents:
        if want_rva and abs(slot_rva - want_rva) <= 0x30:
            print(f'   slot {slot_rva:#x} = {nm}')
        elif want_rva == 0 and k <= 6:
            print(f'   slot {slot_rva:#x} = {nm}')
