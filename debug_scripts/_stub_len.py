import struct
nb = 0x80000000
# copy minimal builder from x86_x64 logic
def build(p1_rva, p2_rva, msg_rva, wcsstr_iat, wcslen_iat, getstd, writefn, exit_iat):
    def va(r): return nb + r
    def ff15(at_rva, iat): return b'\xff\x15' + struct.pack('<i', iat - (va(at_rva) + 6))
    p1 = bytearray()
    def p1_at(): return p1_rva + len(p1)
    def put1(*parts):
        for part in parts: p1.extend(part)
    put1(b'\x48\x83\xec\x28', b'\x48\x8d\x8d\xd8\xfd\xff\xff', b'\x48\x8d\x15')
    lea_disp = len(p1); put1(b'\x00\x00\x00\x00')
    put1(ff15(p1_at(), wcsstr_iat))
    put1(b'\x48\x85\xc0', b'\x0f\x84'); jz_fail = len(p1); put1(b'\x00\x00\x00\x00')
    put1(b'\x48\x8d\x70\x0a', b'\x48\x89\xf1')
    put1(ff15(p1_at(), wcslen_iat))
    put1(b'\x89\xc3', b'\x42\xc7\x04\x5e\x0d\x0a\x00\x00', b'\x83\xc3\x02')
    put1(b'\x48\x89\x74\x24\x20', b'\x89\x5c\x24\x28', b'\xe9')
    j_main = len(p1); put1(b'\x00\x00\x00\x00')
    lea_from = va(p1_rva + lea_disp + 4)
    struct.pack_into('<i', p1, lea_disp, va(msg_rva) - lea_from)
    fail_from = p1_rva + jz_fail + 4
    struct.pack_into('<i', p1, jz_fail, p2_rva - fail_from)
    main_from = p1_rva + j_main + 5
    struct.pack_into('<i', p1, j_main, (p2_rva + 8) - main_from)
    p2 = bytearray()
    put2 = p2.extend
    put2(b'\x31\xc9'); put2(ff15(p2_rva + len(p2), exit_iat))
    put2(b'\x48\x8b\x74\x24\x20')
    put2(b'\x8b\x5c\x24\x28')
    put2(b'\xb9\xf5\xff\xff\xff')
    put2(ff15(p2_rva + len(p2), getstd))
    put2(b'\x48\x89\xc1', b'\x48\x89\xf2', b'\x41\x89\xd8')
    put2(b'\x4c\x8d\x4c\x24\x20', b'\x48\xc7\x44\x24\x18\x00\x00\x00\x00')
    put2(ff15(p2_rva + len(p2), writefn))
    put2(b'\x31\xc9'); put2(ff15(p2_rva + len(p2), exit_iat))
    return bytes(p1), bytes(p2)

iat = nb + 0x200000
p1, p2 = build(0x8F6F, 0x8FED, 0x41490, iat, iat+8, iat+16, iat+24, iat+32)
print('p1', len(p1), 'p2', len(p2), 'fits', len(p1)<=93, len(p2)<=78)
