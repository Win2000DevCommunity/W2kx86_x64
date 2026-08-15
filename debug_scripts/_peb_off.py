import ctypes as C
from ctypes import wintypes

# Read our own PEB CommandLine via documented offsets
class UNICODE_STRING(C.Structure):
    _fields_ = [('Length', wintypes.USHORT), ('MaximumLength', wintypes.USHORT),
                ('Buffer', C.c_wchar_p)]

k32 = C.WinDLL('kernel32', use_last_error=True)
ntdll = C.WinDLL('ntdll')

# NtQueryInformationProcess or just gs
# Use GetCommandLineW and also walk PEB
GetCommandLineW = k32.GetCommandLineW
GetCommandLineW.restype = C.c_wchar_p
print('GetCommandLineW:', GetCommandLineW())

# Read PEB via NtCurrentTeb
class TEB(C.Structure):
    _fields_ = [('pad', C.c_byte * 0x60), ('ProcessEnvironmentBlock', C.c_void_p)]

# Use __readgsqword via inline - or NtQuery
ProcessBasicInformation = 0
class PROCESS_BASIC_INFORMATION(C.Structure):
    _fields_ = [('Reserved1', C.c_void_p), ('PebBaseAddress', C.c_void_p),
                ('Reserved2', C.c_void_p*2), ('UniqueProcessId', C.c_void_p),
                ('Reserved3', C.c_void_p)]

NtQueryInformationProcess = ntdll.NtQueryInformationProcess
pbi = PROCESS_BASIC_INFORMATION()
status = NtQueryInformationProcess(-1, 0, C.byref(pbi), C.sizeof(pbi), None)
print('status', hex(status & 0xffffffff), 'peb', hex(pbi.PebBaseAddress or 0))
peb = pbi.PebBaseAddress
# ProcessParameters at PEB+0x20
pp = C.c_void_p.from_address(peb + 0x20).value
print('ProcessParameters', hex(pp or 0))
# dump qwords at pp+0x60 .. pp+0x90
for off in range(0x60, 0x90, 8):
    q = C.c_uint64.from_address(pp + off).value
    print('  pp+%#x = %#x'%(off,q))
# try Buffer at 0x70
buf70 = C.c_void_p.from_address(pp + 0x70).value
buf78 = C.c_void_p.from_address(pp + 0x78).value
print('as ptr +0x70', hex(buf70 or 0))
print('as ptr +0x78', hex(buf78 or 0))
if buf70:
    try:
        print('str70', C.wstring_at(buf70)[:120])
    except Exception as ex:
        print('str70 err', ex)
if buf78:
    try:
        print('str78', C.wstring_at(buf78)[:120])
    except Exception as ex:
        print('str78 err', ex)
# UNICODE_STRING at 0x68
us_len = C.c_uint16.from_address(pp + 0x68).value
print('CommandLine Length at +0x68:', us_len)