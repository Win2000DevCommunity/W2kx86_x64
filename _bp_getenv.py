import ctypes as C
import time
import sys
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
sys.path.insert(0, ".")
import dbg_fault as df

cmdline = r"build_envfix2\cmd_pure.exe /c echo w2ktest"
si = df.STARTUPINFO(); si.cb = C.sizeof(si)
pi = df.PROCESS_INFORMATION()
df.k32.CreateProcessW(None, cmdline, None, None, False,
    df.DEBUG_PROCESS | df.DEBUG_ONLY_THIS_PROCESS, None,
    r"build_envfix2", C.byref(si), C.byref(pi))

class CTX(C.Structure):
    _fields_ = [
        ("P1Home", C.c_uint64),("P2Home", C.c_uint64),("P3Home", C.c_uint64),
        ("P4Home", C.c_uint64),("P5Home", C.c_uint64),("P6Home", C.c_uint64),
        ("ContextFlags", C.c_uint32),("MxCsr", C.c_uint32),
        ("SegCs", C.c_uint16),("SegDs", C.c_uint16),("SegEs", C.c_uint16),
        ("SegFs", C.c_uint16),("SegGs", C.c_uint16),("SegSs", C.c_uint16),
        ("EFlags", C.c_uint32),
        ("Dr0", C.c_uint64),("Dr1", C.c_uint64),("Dr2", C.c_uint64),("Dr3", C.c_uint64),
        ("Dr6", C.c_uint64),("Dr7", C.c_uint64),
        ("Rax", C.c_uint64),("Rcx", C.c_uint64),("Rdx", C.c_uint64),("Rbx", C.c_uint64),
        ("Rsp", C.c_uint64),("Rbp", C.c_uint64),("Rsi", C.c_uint64),("Rdi", C.c_uint64),
        ("R8", C.c_uint64),("R9", C.c_uint64),("R10", C.c_uint64),("R11", C.c_uint64),
        ("R12", C.c_uint64),("R13", C.c_uint64),("R14", C.c_uint64),("R15", C.c_uint64),
        ("Rip", C.c_uint64),
    ]

CTX_ALL = 0x10001F
CALL_BP = RET_BP = None
call_orig = ret_orig = None
hit = 0
t0 = time.time()
while time.time() - t0 < 30:
    ev = df.DEBUG_EVENT()
    if not df.k32.WaitForDebugEvent(C.byref(ev), 1000):
        continue
    code = ev.dwDebugEventCode
    if code == df.CREATE_PROCESS_DEBUG_EVENT:
        base = ev.u.CreateProcessInfo.lpBaseOfImage
        base = base if isinstance(base, int) else C.cast(base, C.c_void_p).value
        CALL_BP = base + 0x49056
        RET_BP = base + 0x49058
        call_orig = df.read_process_mem(pi.hProcess, CALL_BP, 1)[0]
        ret_orig = df.read_process_mem(pi.hProcess, RET_BP, 1)[0]
        df.patch_byte(pi.hProcess, CALL_BP, 0xCC)
        print("armed")
    elif code == df.EXCEPTION_DEBUG_EVENT:
        exc = ev.u.Exception.ExceptionRecord
        eaddr = exc.ExceptionAddress
        eaddr = eaddr if isinstance(eaddr, int) else C.cast(eaddr, C.c_void_p).value
        if exc.ExceptionCode == 0x80000003:
            ctx = CTX(); ctx.ContextFlags = CTX_ALL
            df.k32.GetThreadContext(pi.hThread, C.byref(ctx))
            if CALL_BP and eaddr == CALL_BP:
                hit += 1
                name = df.read_process_mem(pi.hProcess, ctx.Rcx, 32)
                nm = name.decode("utf-16-le","replace").split("\x00")[0] if name else None
                print("CALL%d name=%r r8=%#x" % (hit, nm, ctx.R8))
                df.patch_byte(pi.hProcess, CALL_BP, call_orig)
                df.patch_byte(pi.hProcess, RET_BP, 0xCC)
                ctx.Rip = CALL_BP
                df.k32.SetThreadContext(pi.hThread, C.byref(ctx))
            elif RET_BP and eaddr == RET_BP:
                eax = ctx.Rax & 0xffffffff
                buf = df.read_process_mem(pi.hProcess, 0x80062b00, 32)
                bs = buf.decode("utf-16-le","replace").split("\x00")[0][:60] if buf else None
                print("RET%d eax=%d buf=%r" % (hit, eax, bs))
                df.patch_byte(pi.hProcess, RET_BP, ret_orig)
                ctx.Rip = RET_BP
                df.k32.SetThreadContext(pi.hThread, C.byref(ctx))
                if hit >= 3:
                    df.k32.TerminateProcess(pi.hProcess, 1)
                    break
                df.patch_byte(pi.hProcess, CALL_BP, 0xCC)
        elif exc.ExceptionCode == 0xC0000005:
            print("AV at %#x" % eaddr)
            break
    elif code == df.EXIT_PROCESS_DEBUG_EVENT:
        print("exit", ev.u.ExitProcess.dwExitCode)
        break
    df.k32.ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, df.DBG_CONTINUE)
