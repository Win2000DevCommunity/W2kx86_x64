import pefile
import struct

pe86 = pefile.PE(r'C:\Users\win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU\cmd.exe')

print('Original x86 cmd.exe sections:')
for sec in pe86.sections:
    name = sec.Name.rstrip(b'\x00').decode()
    va = sec.VirtualAddress
    vs = sec.Misc_VirtualSize
    print(f'  {name}: VA=0x{va:X} Size=0x{vs:X}')

# Find IAT slot addresses for shim-mapped functions
SHIM_FUNCS = [
    'GetVDMCurrentDirectories', 'InitializeCriticalSection', 'LeaveCriticalSection',
    'EnterCriticalSection', 'VirtualQuery', 'InterlockedExchange',
    'longjmp', 'towupper', '_get_osfhandle', 'towlower',
    '_except_handler3', '_setjmp3', '_seh_longjmp_unwind',
    '__p___initenv', '_adjust_fdiv', '__p__commode', '__p__fmode'
]

print('\nShim-mapped function IAT slots (x86 original):')
iat_slots = {}
for entry in pe86.DIRECTORY_ENTRY_IMPORT:
    dll = entry.dll.decode().lower() if entry.dll else ''
    for imp in entry.imports:
        name = imp.name.decode() if imp.name else ''
        if name in SHIM_FUNCS:
            iat_va = imp.address  # This includes ImageBase (0x4AD00000)
            iat_rva = iat_va - pe86.OPTIONAL_HEADER.ImageBase
            # Find which section this IAT is in
            sec_name = 'unknown'
            for sec in pe86.sections:
                sva = sec.VirtualAddress
                svs = sec.Misc_VirtualSize
                if sva <= iat_rva < sva + svs:
                    sec_name = sec.Name.rstrip(b'\x00').decode()
                    break
            print(f'  {dll}!{name}: IAT RVA=0x{iat_rva:X} VA=0x{iat_va:X} section={sec_name}')
            iat_slots[name] = iat_rva

# Check if the .text section contains FF 15 thunks that reference these IAT slots
print('\nSearching .text for FF 15 calls to shim IAT slots:')
for sec in pe86.sections:
    name = sec.Name.rstrip(b'\x00').decode()
    if name == '.text':
        text_data = sec.get_data()
        text_va = sec.VirtualAddress
        for func_name, iat_rva in sorted(iat_slots.items(), key=lambda x: x[1]):
            iat_va = iat_rva + pe86.OPTIONAL_HEADER.ImageBase
            pattern = b'\xFF\x15' + struct.pack('<I', iat_va)
            count = text_data.count(pattern)
            if count > 0:
                print(f'  {func_name} (IAT 0x{iat_rva:X}): {count} direct FF 15 calls')
