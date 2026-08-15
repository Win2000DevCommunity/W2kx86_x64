import pefile, struct
pe = pefile.PE('build_out182/w2kshim64.dll')
ed_rva = pe.OPTIONAL_HEADER.DATA_DIRECTORY[0].VirtualAddress
print(f"Export directory RVA: 0x{ed_rva:X}")

for s in pe.sections:
    if b'.edata' in s.Name:
        edata_data = s.get_data()
        edata_rva = s.VirtualAddress
        break

off = ed_rva - edata_rva
hdr = edata_data[off:off+40]
chars, ts, maj, min, name_rva, base, nfuncs, nnames, funcs_rva, names_rva, ords_rva = struct.unpack_from('<IIHHIIIIIII', hdr, 0)
print(f"Base={base}, NumFuncs={nfuncs}, NumNames={nnames}")
print(f"FuncsRVA=0x{funcs_rva:X}, NamesRVA=0x{names_rva:X}, OrdsRVA=0x{ords_rva:X}")

func_off = funcs_rva - edata_rva
name_off_base = names_rva - edata_rva
ord_off_base = ords_rva - edata_rva

print("\nName table (sorted):")
for i in range(nnames):
    name_ptr_rva = struct.unpack_from('<I', edata_data, name_off_base + i*4)[0]
    ordinal = struct.unpack_from('<H', edata_data, ord_off_base + i*2)[0]
    name_str = edata_data[name_ptr_rva - edata_rva:].split(b'\x00')[0]
    func_rva = struct.unpack_from('<I', edata_data, func_off + (ordinal - base)*4)[0]
    print(f'  name="{name_str.decode():25s}" ord={ordinal:2d} func_rva=0x{func_rva:05X}')
