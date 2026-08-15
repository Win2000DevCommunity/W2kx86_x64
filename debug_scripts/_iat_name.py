import struct, sys

path = sys.argv[1] if len(sys.argv) > 1 else r'C:\Users\win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU\cmd.exe'
iat_rva = int(sys.argv[2], 16) if len(sys.argv) > 2 else 0x4ad010b0

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
print('sections:', [(n.decode(), hex(va), hex(vs)) for n, va, vs, ra, rs in sects])

def rva_to_off(rva):
    for name, va, vs, ra, rs in sects:
        if va <= rva < va + max(vs, rs):
            return ra + (rva - va)
    return None

# data dir 1 = import table
od = e + 24 + 112
imp_rva = struct.unpack_from('<I', f, od + 8)[0]
imp_sz = struct.unpack_from('<I', f, od + 12)[0]
print('import dir rva', hex(imp_rva), 'size', hex(imp_sz))

off = rva_to_off(imp_rva)
ofs = off
while True:
    d = struct.unpack_from('<IIIII', f, ofs)
    oft, ts, name, first_thunk, orig_thunk = d
    if oft == 0 and ts == 0 and name == 0:
        break
    no = rva_to_off(name)
    dll = f[no:f.index(b'\x00', no)].decode('latin1')
    # iterate thunks
    to = rva_to_off(first_thunk)
    if to is None:
        ofs += 20
        continue
    entries = []
    k = 0
    while True:
        val = struct.unpack_from('<I', f, to + k * 4)[0]
        if val == 0:
            break
        if val & 0x80000000:
            entries.append((first_thunk + k * 4, val & 0x7FFF, '<ordinal>'))
        else:
            ho = rva_to_off(val)
            if ho is None:
                entries.append((first_thunk + k * 4, val, '?'))
            else:
                hname = f[ho + 2:f.index(b'\x00', ho + 2)].decode('latin1')
                entries.append((first_thunk + k * 4, val, hname))
        k += 1
    for slot_rva, hint, fn in entries:
        if slot_rva == iat_rva:
            print(f'IAT {hex(iat_rva)} -> {dll}!{fn}')
    ofs += 20
