import pefile
import struct

pe = pefile.PE(r'C:\Users\win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU\cmd.exe')

for sec in pe.sections:
    if b'.text' in sec.Name:
        td = sec.get_data()
        tv = sec.VirtualAddress
        break

targets = [0x1A760, 0x1A766, 0x1A7A0, 0x1A584, 0x1A58A]
for t in targets:
    cnt = 0
    i = 0
    while i < len(td) - 5:
        if td[i] == 0xE8:
            rel = struct.unpack_from('<i', td, i + 1)[0]
            tgt = (tv + i + 5 + rel) & 0xFFFFFFFF
            if tgt == t:
                cnt += 1
                if cnt <= 3:
                    print(f'E8 call to thunk 0x{t:X} at RVA 0x{tv+i:X}')
            i += 5
        else:
            i += 1
    print(f'Thunk 0x{t:X}: {cnt} E8 calls')
