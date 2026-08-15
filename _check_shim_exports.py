import struct

with open('build_univ351/w2kshim64.dll', 'rb') as f:
    d = f.read()

po = struct.unpack_from('<I', d, 0x3C)[0]
oho = po + 4 + 20
ohs = struct.unpack_from('<H', d, po + 20)[0]
sho = oho + ohs

# Find the section containing export dir
ed_rva = struct.unpack_from('<I', d, oho + 112)[0]
ef = None
sv = svs = sr = 0
for i in range(10):
    so = sho + i * 40
    sv = struct.unpack_from('<I', d, so + 12)[0]
    svs = struct.unpack_from('<I', d, so + 8)[0]
    sr = struct.unpack_from('<I', d, so + 20)[0]
    if sv <= ed_rva < sv + svs:
        ef = ed_rva - sv + sr
        break

print(f'Export dir at file offset 0x{ef:X}')
ed = d[ef:ef + 40]
base = struct.unpack_from('<I', ed, 16)[0]
nf = struct.unpack_from('<I', ed, 20)[0]
nn = struct.unpack_from('<I', ed, 24)[0]
ar = struct.unpack_from('<I', ed, 28)[0]
nr = struct.unpack_from('<I', ed, 32)[0]
or_ = struct.unpack_from('<I', ed, 36)[0]

af = ar - sv + sr
nf_off = nr - sv + sr
of_off = or_ - sv + sr

print(f'Base={base} Funcs={nf} Names={nn}')
print(f'Address table at file 0x{af:X}')
print(f'Name ptr table at file 0x{nf_off:X}')
print(f'Ordinal table at file 0x{of_off:X}')

print('\nFunction address table:')
for i in range(nf):
    rva = struct.unpack_from('<I', d, af + i * 4)[0]
    print(f'  [{i}] ordinal={i+base} RVA=0x{rva:X}')

print('\nOrdinal table (maps name[i] to ordinal):')
for i in range(nn):
    ord_val = struct.unpack_from('<H', d, of_off + i * 2)[0]
    idx = ord_val - base
    func_rva = struct.unpack_from('<I', d, af + idx * 4)[0]
    print(f'  name[{i}] ordinal={ord_val} -> func[{idx}] RVA=0x{func_rva:X}')

print('\nName pointer table -> names:')
for i in range(nn):
    name_rva = struct.unpack_from('<I', d, nf_off + i * 4)[0]
    # Convert name_rva to file offset
    for j in range(10):
        so = sho + j * 40
        sv_j = struct.unpack_from('<I', d, so + 12)[0]
        svs_j = struct.unpack_from('<I', d, so + 8)[0]
        sr_j = struct.unpack_from('<I', d, so + 20)[0]
        if sv_j <= name_rva < sv_j + svs_j:
            name_foff = name_rva - sv_j + sr_j
            # Read null-terminated string
            end = d.find(b'\x00', name_foff)
            name = d[name_foff:end].decode('ascii', errors='replace')
            print(f'  name[{i}] RVA=0x{name_rva:X} -> "{name}"')
            break
