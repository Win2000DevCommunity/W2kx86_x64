import ctypes as C, struct, sys, time
from pathlib import Path
sys.path.insert(0, ".")
import dbg_fault as df
df.suppress_fault_ui()

k32 = df.k32
exe = str(Path("build_univ99/cmd_pure.exe").resolve())
FF31 = 0x8001E68C
ADD9 = 0x800146F4

si = df.STARTUPINFO(); si.cb = C.sizeof(si)
pi = df.PROCESS_INFORMATION()
cmd = f'"{exe}" /c echo w2ktest'
ok = k32.CreateProcessW(exe, cmd, None, None, False, df.DEBUG_ONLY_THIS_PROCESS, None,
                        str(Path(exe).parent), C.byref(si), C.byref(pi))
assert ok
bps = {}
ev = df.DEBUG_EVENT()
hProcess = None
t0 = time.time()
ff_hits = 0
done = False

def set_bp(proc, addr):
    if addr in bps: return
    b = df.read_process_mem(proc, addr, 1)
    if not b: return
    bps[addr] = b[0]
    wr = C.c_size_t(0)
    k32.WriteProcessMemory(proc, C.c_void_p(addr), b"\xCC", 1, C.byref(wr))

def clear_bp(proc, addr):
    wr = C.c_size_t(0)
    k32.WriteProcessMemory(proc, C.c_void_p(addr), bytes([bps[addr]]), 1, C.byref(wr))

while not done and time.time() - t0 < 12:
    if not k32.WaitForDebugEvent(C.byref(ev), 400):
        continue
    code = ev.dwDebugEventCode
    cont = df.DBG_CONTINUE
    handled = False
    if code == df.CREATE_PROCESS_DEBUG_EVENT:
        hProcess = ev.u.CreateProcessInfo.hProcess
        set_bp(hProcess, FF31)
        set_bp(hProcess, ADD9)
        print("bps set")
    elif code == df.EXCEPTION_DEBUG_EVENT:
        er = ev.u.Exception.ExceptionRecord
        ec = er.ExceptionCode & 0xFFFFFFFF
        addr = er.ExceptionAddress or 0
        if ec == 0x80000003 and addr in bps:
            th = k32.OpenThread(0x1F03FF, False, ev.dwThreadId)
            ctx = df.get_thread_context(th)
            ret = struct.unpack("<Q", df.read_process_mem(hProcess, ctx.Rsp, 8) or b"\0"*8)[0]
            if addr == FF31:
                ff_hits += 1
                if ff_hits <= 8:
                    print(f"[ff31 #{ff_hits}] RCX={ctx.Rcx:#x} RDX={ctx.Rdx:#x} ret={ret:#x} rva={ret-0x80000000:#x}")
            elif addr == ADD9:
                print(f"[add9] RCX={ctx.Rcx:#x} RDX={ctx.Rdx:#x} ret={ret:#x} rva={ret-0x80000000:#x}")
                done = True
            # step over bp
            clear_bp(hProcess, addr)
            ctx.Rip = addr
            ctx.EFlags |= 0x100
            ctx.ContextFlags = df.CONTEXT_FULL
            k32.SetThreadContext(th, C.byref(ctx))
            k32.ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, df.DBG_CONTINUE)
            # wait single step
            while True:
                k32.WaitForDebugEvent(C.byref(ev), 2000)
                if ev.dwDebugEventCode == df.EXCEPTION_DEBUG_EVENT:
                    er2 = ev.u.Exception.ExceptionRecord
                    if (er2.ExceptionCode & 0xFFFFFFFF) == 0x80000004:
                        ctx2 = df.get_thread_context(th)
                        ctx2.EFlags &= ~0x100
                        ctx2.ContextFlags = df.CONTEXT_FULL
                        k32.SetThreadContext(th, C.byref(ctx2))
                        if not done:
                            set_bp(hProcess, addr)
                        k32.ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, df.DBG_CONTINUE)
                        break
                    k32.ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, df.DBG_EXCEPTION_NOT_HANDLED)
                else:
                    k32.ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, df.DBG_CONTINUE)
            k32.CloseHandle(th)
            handled = True
        elif ec == 0xC0000005:
            print("AV"); done = True
            cont = df.DBG_EXCEPTION_NOT_HANDLED
    elif code == df.EXIT_PROCESS_DEBUG_EVENT:
        done = True
    if not handled:
        k32.ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, cont)

print("ff_hits total", ff_hits)
try: k32.TerminateProcess(pi.hProcess, 1)
except Exception: pass
