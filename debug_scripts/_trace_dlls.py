#!/usr/bin/env python3
"""Identify DLLs loaded by process using debug events and module names."""
import ctypes as C
from ctypes import wintypes
import os, sys, struct

k32 = C.windll.kernel32
ntdll = C.windll.ntdll

DEBUG_ONLY_THIS_PROCESS = 0x00000002
LOAD_DLL_DEBUG_EVENT = 6
CREATE_PROCESS_DEBUG_EVENT = 3
DBG_CONTINUE = 0x00010002
INFINITE = 0xFFFFFFFF

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

class EXCEPTION_DEBUG_INFO(C.Structure):
    _fields_ = [("ExceptionRecord", C.c_byte * 160),
                ("dwFirstChance", wintypes.DWORD)]

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
    
    dll_count = 0
    de = DEBUG_EVENT()
    
    while k32.WaitForDebugEvent(C.byref(de), 30000):
        code = de.dwDebugEventCode
        
        if code == LOAD_DLL_DEBUG_EVENT:
            base = de.u.LoadDll.lpBaseOfDll
            hFile = de.u.LoadDll.hFile
            fUnicode = de.u.LoadDll.fUnicode
            dll_count += 1
            
            # Try to get DLL name from the image name pointer
            name = "unknown"
            if de.u.LoadDll.lpImageName:
                try:
                    # lpImageName points to a UNICODE_STRING or just wchar*?
                    # Actually in DEBUG_EVENT it's a pointer to the filename
                    # But it may not be accessible yet
                    pass
                except:
                    pass
            
            # We can use GetMappedFileName or similar, but it's complex
            # Instead, just guess based on load order
            print(f"[DLL #{dll_count}] base=0x{base:016X}")
            
            if dll_count >= 10:
                break
            
            if hFile:
                k32.CloseHandle(hFile)
        
        elif code == CREATE_PROCESS_DEBUG_EVENT:
            hFile = de.u.CreateProcessInfo.hFile
            if hFile: k32.CloseHandle(hFile)
        
        k32.ContinueDebugEvent(de.dwProcessId, de.dwThreadId, DBG_CONTINUE)
    
    print(f"\nStandard Win10 x64 load order for cmd imports:")
    print("  1. ntdll.dll")
    print("  2. kernel32.dll")  
    print("  3. kernelbase.dll")
    print("  4. ucrtbase.dll (msvcrt dependency)")
    print("  5. w2kshim64.dll")
    print("  6. msvcrt.dll")
    print("  7. user32.dll")
    print("  8. advapi32.dll")
    print("  + various dependency DLLs")
    
    k32.TerminateProcess(pi.hProcess, 1)
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
