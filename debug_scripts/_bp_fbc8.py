import ctypes as C, struct, sys, time
from pathlib import Path
sys.path.insert(0, ".")
import dbg_fault as df
df.suppress_fault_ui()
k32 = df.k32
exe = str(Path("build_univ99p/cmd_pure.exe").resolve())
ADD9 = 0x800146F4
FBC8 = 0x8006DBC8
C8D8 = 0x8006A8D8
si = df.STARTUPINFO(); si.cb = C.sizeof(si)
pi = df.PROCESS_INFORMATION()
cmd = f'"{exe}" /c echo w2ktest'
ok = k32.CreateProcessW(exe, cmd, None, None, False, df.DEBUG_ONLY_THIS_PROCESS, None,
                        str(Path(exe).parent), C.byref(si), C.byref(pi))
assert ok
ev = df.DEBUG_EVENT(); hProcess=None; t0=time.time(); orig=None
while time.time()-t0 < 10:
    if not k32.WaitForDebugEvent(C.byref(ev), 400): continue
    if ev.dwDebugEventCode == df.CREATE_PROCESS_DEBUG_EVENT:
        hProcess = ev.u.CreateProcessInfo.hProcess
        orig = df.read_process_mem(hProcess, ADD9, 1)[0]
        wr=C.c_size_t(0); k32.WriteProcessMemory(hProcess, C.c_void_p(ADD9), b"\xCC", 1, C.byref(wr))
    elif ev.dwDebugEventCode == df.EXCEPTION_DEBUG_EVENT:
        er = ev.u.Exception.ExceptionRecord
        if (er.ExceptionCode & 0xffffffff) == 0x80000003 and er.ExceptionAddress == ADD9:
            th = k32.OpenThread(0x1F03FF, False, ev.dwThreadId)
            ctx = df.get_thread_context(th)
            fbc8 = struct.unpack("<Q", df.read_process_mem(hProcess, FBC8, 8) or b"\0"*8)[0]
            # also dword
            fbc8d = struct.unpack("<I", df.read_process_mem(hProcess, FBC8, 4) or b"\0"*4)[0]
            c8 = struct.unpack("<Q", df.read_process_mem(hProcess, C8D8, 8) or b"\0"*8)[0]
            print(f"RCX={ctx.Rcx:#x} RDX={ctx.Rdx:#x}")
            print(f"[c8d8]={c8:#x} [fbc8] qword={fbc8:#x} dword={fbc8d:#x}")
            for name,a in [("rcx",ctx.Rcx),("fbc8d",fbc8d),("c8",c8)]:
                b = df.read_process_mem(hProcess, a & 0xffffffffffffffff, 64) if a else b""
                if b:
                    s = b.decode("utf-16-le","replace").split("\x00")[0][:80]
                    print(f"  @{name}: {s!r}")
            k32.CloseHandle(th)
            k32.TerminateProcess(pi.hProcess, 1)
            break
        elif (er.ExceptionCode & 0xffffffff) == 0xC0000005:
            print("AV before add9"); break
    k32.ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, df.DBG_CONTINUE)
