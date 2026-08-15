#!/usr/bin/env python3
"""Get crash call stack by reading return address from stack."""
import ctypes as C
from ctypes import wintypes
import os, sys, struct

k32 = C.windll.kernel32
ntdll = C.windll.ntdll

DEBUG_ONLY_THIS_PROCESS = 0x00000002
EXCEPTION_DEBUG_EVENT = 1
CREATE_PROCESS_DEBUG_EVENT = 3
LOAD_DLL_DEBUG_EVENT = 6
EXIT_PROCESS_DEBUG_EVENT = 5
DBG_CONTINUE = 0x00010002
DBG_EXCEPTION_NOT_HANDLED = 0x80010001

ULONGLONG = C.c_ulonglong

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
                ("ExceptionInformation", ULONGLONG * 15)]

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

class CONTEXT(C.Structure):
    _fields_ = [
        ("P1Home", ULONGLONG), ("P2Home", ULONGLONG),
        ("P3Home", ULONGLONG), ("P4Home", ULONGLONG),
        ("P5Home", ULONGLONG), ("P6Home", ULONGLONG),
        ("ContextFlags", wintypes.DWORD), ("MxCsr", wintypes.DWORD),
        ("SegCs", wintypes.WORD), ("SegDs", wintypes.WORD),
        ("SegEs", wintypes.WORD), ("SegFs", wintypes.WORD),
        ("SegGs", wintypes.WORD), ("SegSs", wintypes.WORD),
        ("EFlags", wintypes.DWORD),
        ("Dr0", ULONGLONG), ("Dr1", ULONGLONG),
        ("Dr2", ULONGLONG), ("Dr3", ULONGLONG),
        ("Dr6", ULONGLONG), ("Dr7", ULONGLONG),
        ("Rax", ULONGLONG), ("Rcx", ULONGLONG),
        ("Rdx", ULONGLONG), ("Rbx", ULONGLONG),
        ("Rsp", ULONGLONG), ("Rbp", ULONGLONG),
        ("Rsi", ULONGLONG), ("Rdi", ULONGLONG),
        ("R8", ULONGLONG), ("R9", ULONGLONG),
        ("R10", ULONGLONG), ("R11", ULONGLONG),
        ("R12", ULONGLONG), ("R13", ULONGLONG),
        ("R14", ULONGLONG), ("R15", ULONGLONG),
        ("Rip", ULONGLONG)]
CONTEXT_FULL = 0x10007

def main():
    exe = os.path.abspath(sys.argv[1])
    args = ' '.join(f'"{a}"' for a in sys.argv[2:]) if len(sys.argv) > 2 else '/c echo w2ktest'
    si = STARTUPINFOW(); si.cb = C.sizeof(STARTUPINFOW)
    pi = PROCESS_INFORMATION()
    ok = k32.CreateProcessW(exe, args, None, None, False, DEBUG_ONLY_THIS_PROCESS,
                           None, os.path.dirname(exe) or None, C.byref(si), C.byref(pi))
    if not ok:
        print(f"CreateProcess failed: {C.get_last_error()}"); return 1
    
    main_base = None
    shim_base = None
    dll_bases = {}
    
    de = DEBUG_EVENT()
    while k32.WaitForDebugEvent(C.byref(de), 30000):
        code = de.dwDebugEventCode
        
        if code == CREATE_PROCESS_DEBUG_EVENT:
            main_base = de.u.CreateProcessInfo.lpBaseOfImage
            hf = de.u.CreateProcessInfo.hFile
            if hf: k32.CloseHandle(hf)
        
        elif code == LOAD_DLL_DEBUG_EVENT:
            base = de.u.LoadDll.lpBaseOfDll
            dll_bases[base] = len(dll_bases) + 1
            hf = de.u.LoadDll.hFile
            if hf: k32.CloseHandle(hf)
        
        elif code == EXCEPTION_DEBUG_EVENT:
            er = de.u.Exception.ExceptionRecord
            ec = er.ExceptionCode
            
            if ec == 0x80000003:  # Initial breakpoint - skip
                k32.ContinueDebugEvent(de.dwProcessId, de.dwThreadId, DBG_CONTINUE)
                continue
            
            # Real exception - get context and stack
            ctx = CONTEXT()
            ctx.ContextFlags = CONTEXT_FULL
            k32.GetThreadContext(pi.hThread, C.byref(ctx))
            
            print(f"Exception 0x{ec:08X} at 0x{er.ExceptionAddress:016X}")
            print(f"  RIP=0x{ctx.Rip:016X} RSP=0x{ctx.Rsp:016X}")
            
            # Read return address from stack (caller of crashing function)
            ret_buf = (ULONGLONG * 1)()
            ntdll.NtReadVirtualMemory(pi.hProcess, C.c_void_p(ctx.Rsp), ret_buf, 8, None)
            ret_addr = ret_buf[0]
            
            # Identify which module
            who = "unknown"
            if main_base and main_base <= ret_addr < main_base + 0x200000:
                who = f"main+0x{ret_addr - main_base:X}"
            else:
                for dll_base in sorted(dll_bases.keys()):
                    if dll_base <= ret_addr < dll_base + 0x200000:
                        who = f"DLL#{dll_bases[dll_base]}+0x{ret_addr - dll_base:X}"
                        break
            
            print(f"  Return address (caller): 0x{ret_addr:016X} ({who})")
            
            # Read a few more stack frames
            print(f"  Stack trace (first 8 frames):")
            for frame in range(8):
                rsp_val = ctx.Rsp + frame * 8
                buf = (ULONGLONG * 1)()
                ntdll.NtReadVirtualMemory(pi.hProcess, C.c_void_p(rsp_val), buf, 8, None)
                val = buf[0]
                marker = "<<< RET" if frame == 0 else ""
                w = "unknown"
                if main_base and main_base <= val < main_base + 0x200000:
                    w = f"main+0x{val - main_base:X}"
                else:
                    for dll_base in sorted(dll_bases.keys()):
                        if dll_base <= val < dll_base + 0x200000:
                            w = f"DLL#{dll_bases[dll_base]}+0x{val - dll_base:X}"
                            break
                print(f"    [RSP+{frame*8:02X}] = 0x{val:016X} ({w}) {marker}")
            
            break
        
        elif code == EXIT_PROCESS_DEBUG_EVENT:
            break
        
        k32.ContinueDebugEvent(de.dwProcessId, de.dwThreadId, DBG_CONTINUE)
    
    k32.TerminateProcess(pi.hProcess, 1)

if __name__ == "__main__":
    raise SystemExit(main())
