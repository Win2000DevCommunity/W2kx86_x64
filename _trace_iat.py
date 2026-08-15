#!/usr/bin/env python3
"""Check IAT slot for __p__fmode at runtime to verify it points to shim."""
import ctypes as C
from ctypes import wintypes
import os, sys

k32 = C.windll.kernel32
ntdll = C.windll.ntdll

DEBUG_ONLY_THIS_PROCESS = 0x00000002
EXCEPTION_DEBUG_EVENT = 1
CREATE_PROCESS_DEBUG_EVENT = 3
LOAD_DLL_DEBUG_EVENT = 6
EXIT_PROCESS_DEBUG_EVENT = 5
DBG_CONTINUE = 0x00010002

class STARTUPINFOW(C.Structure):
    _fields_ = [("cb", wintypes.DWORD), ("lpReserved", wintypes.LPWSTR),
                ("lpDesktop", wintypes.LPWSTR), ("lpTitle", wintypes.LPWSTR),
                ("dwX", wintypes.DWORD), ("dwY", wintypes.DWORD),
                ("dwXSize", wintypes.DWORD), ("dwYSize", wintypes.DWORD),
                ("dwXCountChars", wintypes.DWORD), ("dwYCountChars", wintypes.DWORD),
                ("dwFillAttribute", wintypes.DWORD), ("dwFlags", wintypes.DWORD),
                ("wShowWindow", wintypes.WORD), ("cbReserved2", wintypes.WORD),
                ("lpReserved2", C.POINTER(wintypes.BYTE)),
                ("hStdInput", wintypes.HANDLE), ("hStdOutput", wintypes.HANDLE),
                ("hStdError", wintypes.HANDLE)]

class PROCESS_INFORMATION(C.Structure):
    _fields_ = [("hProcess", wintypes.HANDLE), ("hThread", wintypes.HANDLE),
                ("dwProcessId", wintypes.DWORD), ("dwThreadId", wintypes.DWORD)]

class EXCEPTION_RECORD(C.Structure):
    _fields_ = [("ExceptionCode", wintypes.DWORD),
                ("ExceptionFlags", wintypes.DWORD),
                ("ExceptionRecord", C.c_void_p),
                ("ExceptionAddress", C.c_void_p),
                ("NumberParameters", wintypes.DWORD),
                ("ExceptionInformation", C.c_ulonglong * 15)]

class EXCEPTION_DEBUG_INFO(C.Structure):
    _fields_ = [("ExceptionRecord", EXCEPTION_RECORD),
                ("dwFirstChance", wintypes.DWORD)]

class CREATE_PROCESS_DEBUG_INFO(C.Structure):
    _fields_ = [("hFile", wintypes.HANDLE), ("hProcess", wintypes.HANDLE),
                ("hThread", wintypes.HANDLE), ("lpBaseOfImage", C.c_void_p),
                ("dwDebugInfoFileOffset", wintypes.DWORD),
                ("nDebugInfoSize", wintypes.DWORD),
                ("lpThreadLocalBase", C.c_void_p),
                ("lpStartAddress", C.c_void_p),
                ("lpImageName", C.c_void_p), ("fUnicode", wintypes.WORD)]

class LOAD_DLL_DEBUG_INFO(C.Structure):
    _fields_ = [("hFile", wintypes.HANDLE), ("lpBaseOfDll", C.c_void_p),
                ("dwDebugInfoFileOffset", wintypes.DWORD),
                ("nDebugInfoSize", wintypes.DWORD),
                ("lpImageName", C.c_void_p), ("fUnicode", wintypes.WORD)]

class EXIT_PROCESS_DEBUG_INFO(C.Structure):
    _fields_ = [("dwExitCode", wintypes.DWORD)]

class U_DEBUG_INFO(C.Union):
    _fields_ = [("Exception", EXCEPTION_DEBUG_INFO),
                ("CreateProcessInfo", CREATE_PROCESS_DEBUG_INFO),
                ("LoadDll", LOAD_DLL_DEBUG_INFO),
                ("ExitProcess", EXIT_PROCESS_DEBUG_INFO)]

class DEBUG_EVENT(C.Structure):
    _fields_ = [("dwDebugEventCode", wintypes.DWORD),
                ("dwProcessId", wintypes.DWORD),
                ("dwThreadId", wintypes.DWORD),
                ("u", U_DEBUG_INFO)]

def main():
    exe = os.path.abspath(sys.argv[1])
    args = ' '.join(f'"{a}"' for a in sys.argv[2:]) if len(sys.argv) > 2 else '/c echo w2ktest'
    
    si = STARTUPINFOW(); si.cb = C.sizeof(STARTUPINFOW)
    pi = PROCESS_INFORMATION()
    
    ok = k32.CreateProcessW(exe, args, None, None, False, DEBUG_ONLY_THIS_PROCESS,
                           None, os.path.dirname(exe) or None, C.byref(si), C.byref(pi))
    if not ok:
        print(f"CreateProcess failed: {C.get_last_error()}"); return 1
    
    print(f"PID={pi.dwProcessId}")
    main_base = None
    shim_base = None
    iat_checked = False
    
    de = DEBUG_EVENT()
    while k32.WaitForDebugEvent(C.byref(de), 30000):
        code = de.dwDebugEventCode
        
        if code == EXCEPTION_DEBUG_EVENT:
            er = de.u.Exception.ExceptionRecord
            ec = er.ExceptionCode
            
            if ec == 0x80000003:  # Initial breakpoint
                # Read IAT slot for __p__fmode
                # IAT slot VA = 0x800A9EC8 (from disassembly)
                iat_va = 0x800A9EC8
                buf = (C.c_ulonglong * 1)()
                ntdll.NtReadVirtualMemory(pi.hProcess, C.c_void_p(iat_va), buf, 8, None)
                iat_val = buf[0]
                print(f"IAT[0x{iat_va:X}] = 0x{iat_val:016X}")
                
                if shim_base and shim_base <= iat_val < shim_base + 0x10000:
                    offset = iat_val - shim_base
                    print(f"  -> shim+0x{offset:X} (in w2kshim64)")
                elif main_base and main_base <= iat_val < main_base + 0x100000:
                    offset = iat_val - main_base
                    print(f"  -> main+0x{offset:X} (in main binary - WRONG!)")
                else:
                    print(f"  -> unknown module")
                
                # Also read a few more IAT slots to check
                for offset in range(-0x20, 0x60, 8):
                    va = iat_va + offset
                    buf2 = (C.c_ulonglong * 1)()
                    ntdll.NtReadVirtualMemory(pi.hProcess, C.c_void_p(va), buf2, 8, None)
                    val = buf2[0]
                    if val:
                        where = ""
                        if shim_base and shim_base <= val < shim_base + 0x10000:
                            where = f" (shim+0x{val-shim_base:X})"
                        elif main_base and main_base <= val < main_base + 0x100000:
                            where = f" (main+0x{val-main_base:X})"
                        print(f"  IAT[0x{va:X}] = 0x{val:016X}{where}")
                
                iat_checked = True
            
            elif ec == 0xC0000005:
                print(f"ACCESS_VIOLATION at 0x{er.ExceptionAddress:X}")
                break
        
        elif code == LOAD_DLL_DEBUG_EVENT:
            base = de.u.LoadDll.lpBaseOfDll
            if base == 0x1800100000:
                shim_base = base
                print(f"Shim loaded at 0x{base:016X}")
        
        elif code == CREATE_PROCESS_DEBUG_EVENT:
            main_base = de.u.CreateProcessInfo.lpBaseOfImage
            print(f"Main loaded at 0x{main_base:016X}")
        
        elif code == EXIT_PROCESS_DEBUG_EVENT:
            print(f"Exit: 0x{de.u.ExitProcess.dwExitCode:08X}")
            break
        
        k32.ContinueDebugEvent(de.dwProcessId, de.dwThreadId, DBG_CONTINUE)
    
    k32.TerminateProcess(pi.hProcess, 1)
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
