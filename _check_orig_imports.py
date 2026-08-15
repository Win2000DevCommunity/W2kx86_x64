import pefile

pe = pefile.PE(r'C:\Users\win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU\cmd.exe')

print('MSVCRT imports (original x86):')
for entry in pe.DIRECTORY_ENTRY_IMPORT:
    if entry.dll and b'MSVCRT' in entry.dll.upper():
        for i, imp in enumerate(entry.imports):
            name = imp.name.decode() if imp.name else '(ordinal)'
            print(f'  [{i}] {name} hint=0x{imp.hint:04X}')

print('\nFunctions redirected to shim:')
SHIM_MAP = {
    'InterlockedExchange': 'InterlockedExchange',
    'VirtualQuery': 'VirtualQuery',
    'InitializeCriticalSection': 'InitializeCriticalSection',
    'EnterCriticalSection': 'EnterCriticalSection',
    'LeaveCriticalSection': 'LeaveCriticalSection',
    'DeleteCriticalSection': 'DeleteCriticalSection',
    'GetVDMCurrentDirectories': 'GetVDMCurrentDirectories',
    '_setjmp3': '_setjmp3',
    'longjmp': 'longjmp',
    '_except_handler3': '_except_handler3',
    '_seh_longjmp_unwind': '_seh_longjmp_unwind',
    '__p___initenv': '__p___initenv',
    '_adjust_fdiv': '_adjust_fdiv',
    '__p__commode': '__p__commode',
    '__p__fmode': '__p__fmode',
    'towupper': 'towupper',
    'towlower': 'towlower',
    '_get_osfhandle': '_get_osfhandle',
}

print()
print('All kernel32+MSVCRT functions that map to shim (in x86 order):')
for entry in pe.DIRECTORY_ENTRY_IMPORT:
    dll_name = entry.dll.decode().lower() if entry.dll else ''
    for imp in entry.imports:
        name = imp.name.decode() if imp.name else ''
        if name in SHIM_MAP:
            shim_name = SHIM_MAP[name]
            print(f'  {dll_name}!{name} -> shim!{shim_name}')
