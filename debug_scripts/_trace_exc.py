#!/usr/bin/env python3
"""Minimal exception tracer: runs cmd_pure.exe under debugger, stops only on
first EXCEPTION_DEBUG_EVENT, reports full details including whether
w2kshim64.dll loaded and if its DllMain executed."""
import ctypes as C
from ctypes import wintypes
import os, sys, struct

k32 = C.windll.kernel32
ntdll = C.windll.ntdll

DEBUG_PROCESS = 0x00000001
DEBUG_ONLY_THIS_PROCESS = 0x00000002
CREATE_SUSPENDED = 0x00000004
INFINITE = 0xFFFFFFFF

EXCEPTION_DEBUG_EVENT = 1
CREATE_PROCESS_DEBUG_EVENT = 3
LOAD_DLL_DEBUG_EVENT = 6
EXIT_PROCESS_DEBUG_EVENT = 5

DBG_CONTINUE = 0x00010002
DBG_EXCEPTION_NOT_HANDLED = 0x80010001

STATUS_ACCESS_VIOLATION = 0xC0000005
STATUS_BREAKPOINT = 0x80000003

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

ULONGLONG = C.c_ulonglong
class CONTEXT(C.Structure):
    _fields_ = [("P1Home", ULONGLONG), ("P2Home", ULONGLONG),
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
    exe_path = os.path.abspath(sys.argv[1]) if len(sys.argv) > 1 else None
    if not exe_path:
        print("Usage: python _trace_exc.py <cmd_pure.exe> [args...]")
        return 1
    
    args = ' '.join(f'"{a}"' for a in sys.argv[2:]) if len(sys.argv) > 2 else '/c echo w2ktest'
    
    si = STARTUPINFOW()
    si.cb = C.sizeof(STARTUPINFOW)
    pi = PROCESS_INFORMATION()
    
    ok = k32.CreateProcessW(
        exe_path, args, None, None, False,
        DEBUG_ONLY_THIS_PROCESS, None, os.path.dirname(exe_path) or None,
        C.byref(si), C.byref(pi))
    if not ok:
        print(f"CreateProcess failed: {C.get_last_error()}")
        return 1
    
    print(f"Process created: PID={pi.dwProcessId}")
    
    main_base = None
    shim_base = None
    shim_name = b'w2kshim64'
    exception_count = 0
    dll_count = 0
    
    de = DEBUG_EVENT()
    while k32.WaitForDebugEvent(C.byref(de), 30000):
        code = de.dwDebugEventCode
        
        if code == CREATE_PROCESS_DEBUG_EVENT:
            main_base = de.u.CreateProcessInfo.lpBaseOfImage
            print(f"[CREATE_PROCESS] main base = 0x{main_base:016X}")
            hf = de.u.CreateProcessInfo.hFile
            if hf: k32.CloseHandle(hf)
        
        elif code == LOAD_DLL_DEBUG_EVENT:
            base = de.u.LoadDll.lpBaseOfDll
            dll_count += 1
            # Read DLL name
            hf = de.u.LoadDll.hFile
            name = ""
            if hf and de.u.LoadDll.fUnicode:
                # Can't easily read name from handle; just track bases
                pass
            if hf: k32.CloseHandle(hf)
            
            # Check if this looks like our shim DLL
            # w2kshim64 has preferred base 0x1800100000
            # After ASLR relocation, it's usually somewhere in 0x180000000+ range
            # Typical load addresses: main at 0x140000000, shim at 0x180000000+
            if shim_base is None and base and (base >> 32) >= 0x180:
                shim_base = base
                print(f"[LOAD_DLL #{dll_count}] possible shim base = 0x{base:016X}")
            elif dll_count <= 8:
                print(f"[LOAD_DLL #{dll_count}] base = 0x{base:016X}")
        
        elif code == EXCEPTION_DEBUG_EVENT:
            exception_count += 1
            er = de.u.Exception.ExceptionRecord
            ec = er.ExceptionCode
            ea = er.ExceptionAddress
            first = de.u.Exception.dwFirstChance
            flags = er.ExceptionFlags
            
            ctx = CONTEXT()
            ctx.ContextFlags = CONTEXT_FULL
            k32.GetThreadContext(pi.hThread, C.byref(ctx))
            rip = ctx.Rip
            
            print(f"\n[EXCEPTION #{exception_count}]")
            print(f"  Code: 0x{ec:08X} {'(ACCESS_VIOLATION)' if ec==0xC0000005 else ''}")
            print(f"  Address: 0x{ea:016X}" if ea else "  Address: NULL")
            print(f"  FirstChance: {first}")
            print(f"  Flags: 0x{flags:X}")
            print(f"  RIP: 0x{rip:016X}")
            print(f"  RSP: 0x{ctx.Rsp:016X}")
            print(f"  RBP: 0x{ctx.Rbp:016X}")
            print(f"  RAX: 0x{ctx.Rax:016X}  RCX: 0x{ctx.Rcx:016X}")
            print(f"  RDX: 0x{ctx.Rdx:016X}  RBX: 0x{ctx.Rbx:016X}")
            print(f"  RSI: 0x{ctx.Rsi:016X}  RDI: 0x{ctx.Rdi:016X}")
            print(f"  R8:  0x{ctx.R8:016X}  R9:  0x{ctx.R9:016X}")
            print(f"  R10: 0x{ctx.R10:016X}  R11: 0x{ctx.R11:016X}")
            print(f"  R12: 0x{ctx.R12:016X}  R13: 0x{ctx.R13:016X}")
            
            # Check if GS:[0] has SEH frame
            teb_self = (ctx.Rsp >> 12) << 12  # approximate TEB
            print(f"\n  Main base: 0x{main_base:016X}" if main_base else "  Main base: ???")
            print(f"  Shim base: 0x{shim_base:016X}" if shim_base else "  Shim base: NOT DETECTED")
            
            if main_base and rip:
                if main_base <= rip < main_base + 0x100000:
                    print(f"  RIP offset from main: +0x{rip - main_base:X}")
                elif shim_base and shim_base <= rip < shim_base + 0x10000:
                    print(f"  RIP offset from shim: +0x{rip - shim_base:X}")
                else:
                    print(f"  RIP is in system/module (not main/shim)")
            
            # Read the faulting instruction bytes
            try:
                buf = (C.c_ubyte * 16)()
                ntdll.NtReadVirtualMemory(pi.hProcess, C.c_void_p(rip), buf, 16, None)
                hex_bytes = ' '.join(f'{b:02X}' for b in buf)
                print(f"  Code bytes at RIP: {hex_bytes}")
            except:
                pass
            
            # Let the exception go to the process (VEH gets a chance)
            # DBG_EXCEPTION_NOT_HANDLED = the debugger didn't handle it, pass to process
            k32.ContinueDebugEvent(de.dwProcessId, de.dwThreadId, DBG_EXCEPTION_NOT_HANDLED)
            
            # Wait for next event
            de2 = DEBUG_EVENT()
            if k32.WaitForDebugEvent(C.byref(de2), 1000):
                code2 = de2.dwDebugEventCode
                if code2 == EXCEPTION_DEBUG_EVENT:
                    er2 = de2.u.Exception.ExceptionRecord
                    ec2 = er2.ExceptionCode
                    first2 = de2.u.Exception.dwFirstChance
                    if not first2:
                        print(f"\n  ** SECOND-CHANCE exception! Code=0x{ec2:08X}")
                        print(f"  ** VEH/SEH did NOT handle the first-chance exception!")
                    else:
                        print(f"\n  ** Another first-chance exception: 0x{ec2:08X}")
                    k32.ContinueDebugEvent(de2.dwProcessId, de2.dwThreadId, DBG_CONTINUE)
                elif code2 == EXIT_PROCESS_DEBUG_EVENT:
                    exit_code = de2.u.ExitProcess.dwExitCode
                    print(f"\n  Process exited after exception: 0x{exit_code:08X}")
                    k32.ContinueDebugEvent(de2.dwProcessId, de2.dwThreadId, DBG_CONTINUE)
                    break
                else:
                    k32.ContinueDebugEvent(de2.dwProcessId, de2.dwThreadId, DBG_CONTINUE)
            
            if exception_count >= 3:
                print("\n3 exceptions reached - terminating analysis")
                break
            
            # Continue for more exceptions
            continue
        
        elif code == EXIT_PROCESS_DEBUG_EVENT:
            exit_code = de.u.ExitProcess.dwExitCode
            print(f"\n[EXIT] Process exited: 0x{exit_code:08X} ({exit_code & 0xFFFFFFFF})")
            k32.ContinueDebugEvent(de.dwProcessId, de.dwThreadId, DBG_CONTINUE)
            break
        
        k32.ContinueDebugEvent(de.dwProcessId, de.dwThreadId, DBG_CONTINUE)
    
    k32.TerminateProcess(pi.hProcess, 1)
    print(f"\nSummary: {exception_count} exception(s), shim_loaded={shim_base is not None}")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
