import pefile

pe = pefile.PE(r'C:\Users\win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU\cmd.exe')

# Get all IAT RVAs and their functions
all_iat = []
for entry in pe.DIRECTORY_ENTRY_IMPORT:
    dll = entry.dll.decode().lower() if entry.dll else ''
    for imp in entry.imports:
        name = imp.name.decode() if imp.name else '(ordinal)'
        iat_rva = imp.address - pe.OPTIONAL_HEADER.ImageBase
        all_iat.append((iat_rva, dll, name))

all_iat.sort()
print('All IAT slots in x86 original (0x1000-0x1300 range):')
for rva, dll, name in all_iat:
    if 0x1000 <= rva <= 0x1300:
        marker = ' <-- SHIM' if name in ('longjmp', 'towupper', '_get_osfhandle', 'towlower', '_except_handler3', '_setjmp3', '_seh_longjmp_unwind', '__p___initenv', '_adjust_fdiv', '__p__commode', '__p__fmode', 'InterlockedExchange', 'VirtualQuery', 'InitializeCriticalSection', 'EnterCriticalSection', 'LeaveCriticalSection', 'DeleteCriticalSection', 'GetVDMCurrentDirectories') else ''
        print(f'  0x{rva:04X}: {dll}!{name}{marker}')
