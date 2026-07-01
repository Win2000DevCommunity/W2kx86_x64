"""Debug LoadLibrary of w2kshim64.dll — log exceptions + module loads."""
import ctypes as C
import os
import sys

import dbg_fault as df

df.suppress_fault_ui()

DLL = os.path.abspath(
    r"c:\Users\win2000\Desktop\Nouveau dossier\Nouveau dossier (9)\win2000_x64\w2kshim64.dll"
)

code = f"""
import ctypes
k = ctypes.WinDLL('kernel32')
k.SetErrorMode(0x8003)
LoadLibraryW = k.LoadLibraryW
LoadLibraryW.restype = ctypes.c_void_p
h = LoadLibraryW({DLL!r})
print('handle', hex(h or 0), 'err', ctypes.get_last_error())
""".strip()

host = sys.executable
si = df.STARTUPINFO()
si.cb = C.sizeof(df.STARTUPINFO)
pi = df.PROCESS_INFORMATION()
ok = df.k32.CreateProcessW(
    host, C.create_unicode_buffer(f'"{host}" -c "{code}"'),
    None, None, False, df.DEBUG_ONLY_THIS_PROCESS, None, None,
    C.byref(si), C.byref(pi))
if not ok:
    print("CreateProcess failed", C.get_last_error())
    raise SystemExit(1)

n = 0
de = df.DEBUG_EVENT()
while True:
    if not df.k32.WaitForDebugEvent(C.byref(de), df.INFINITE):
        break
    cont = df.DBG_CONTINUE
    if de.dwDebugEventCode == df.LOAD_DLL_DEBUG_EVENT:
        ev = de.u.LoadDll
        print(f"LOAD base=0x{ev.lpBaseOfDll:x}")
        if ev.hFile:
            df.k32.CloseHandle(ev.hFile)
    elif de.dwDebugEventCode == df.EXCEPTION_DEBUG_EVENT:
        er = de.u.Exception.ExceptionRecord
        ecode = er.ExceptionCode & 0xFFFFFFFF
        if ecode not in (0x80000003, 0x80000004):
            ctx = df.CONTEXT()
            ctx.ContextFlags = df.CONTEXT_FULL
            df.k32.GetThreadContext(pi.hThread, C.byref(ctx))
            rip = ctx.Rip
            n += 1
            stk = C.c_ulonglong()
            ra = C.c_ulonglong()
            df.k32.ReadProcessMemory(
                pi.hProcess, C.c_void_p(ctx.Rsp), C.byref(ra), 8, None)
            print(f"  EXC #{n} code=0x{ecode:08x} fc={er.ExceptionFlags} "
                  f"rip=0x{rip:x} rsp=0x{ctx.Rsp:x} [rsp]=0x{ra.value:x}")
            if rip == 0 and ra.value:
                print(f"       ret target would be 0x{ra.value:x}")
            # disassemble a few bytes at rip if non-zero
            if rip:
                buf = (C.c_ubyte * 16)()
                df.k32.ReadProcessMemory(
                    pi.hProcess, C.c_void_p(rip), buf, 16, None)
                print("       bytes", bytes(buf).hex())
            if n >= 6:
                df.k32.TerminateProcess(pi.hProcess, 1)
                break
            cont = df.DBG_EXCEPTION_NOT_HANDLED
    elif de.dwDebugEventCode == df.EXIT_PROCESS_DEBUG_EVENT:
        print("exit", de.u.ExitProcess.dwExitCode)
        break
    df.k32.ContinueDebugEvent(de.dwProcessId, de.dwThreadId, cont)

df.k32.CloseHandle(pi.hThread)
df.k32.CloseHandle(pi.hProcess)
