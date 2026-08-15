import ctypes as C, struct, time, sys, os
sys.path.insert(0, ".")
import dbg_fault as df
df.suppress_fault_ui()
k32 = df.k32
CONTEXT_ALL = df.CONTEXT_FULL | df.CONTEXT_AMD64 | 0x10

EXE = os.path.abspath(r"build_univ258\cmd_pure.exe")
si = df.STARTUPINFO(); si.cb = C.sizeof(si)
pi = df.PROCESS_INFORMATION()
k32.CreateProcessW(None, C.create_unicode_buffer(f'"{EXE}"'), None, None, False,
                    df.DEBUG_PROCESS, None, os.path.dirname(EXE), C.byref(si), C.byref(pi))
base = 0; init = True
de = df.DEBUG_EVENT(); t0 = time.time()
hits = {}
while time.time() - t0 < 4:
    if not k32.WaitForDebugEvent(C.byref(de), 50):
        continue
    code = de.dwDebugEventCode
    if code == 3:
        base = de.u.CreateProcessInfo.lpBaseOfImage or 0
        print("base", hex(base))
    elif code == 1:
        er = de.u.Exception.ExceptionRecord
        ec = er.ExceptionCode & 0xFFFFFFFF
        ea = er.ExceptionAddress or 0
        if ec == 0x80000003 and init:
            init = False
            ctx = df.CONTEXT(); ctx.ContextFlags = CONTEXT_ALL
            k32.GetThreadContext(pi.hThread, C.byref(ctx))
            ctx.Dr0 = base + 0x14974
            ctx.Dr1 = base + 0x1EA3C
            ctx.Dr2 = base + 0x14818  # AC92
            ctx.Dr7 = 0x55
            k32.SetThreadContext(pi.hThread, C.byref(ctx))
            print("armed")
        elif ec == 0x80000004:
            ctx = df.CONTEXT(); ctx.ContextFlags = CONTEXT_ALL
            k32.GetThreadContext(pi.hThread, C.byref(ctx))
            rva = (ctx.Rip - base) & 0xffffffffffffffff
            key = rva
            hits[key] = hits.get(key, 0) + 1
            if hits[key] <= 3 or hits[key] % 50 == 0:
                print(f"HW rva={rva:#x} count={hits[key]} rsp={ctx.Rsp:#x}")
            ctx.Dr6 = 0; ctx.EFlags |= 0x10000
            k32.SetThreadContext(pi.hThread, C.byref(ctx))
            if hits.get(0x14974, 0) > 200:
                print("recursive 14974 - abort"); break
        elif ec == 0xC00000FD:
            print("STACK OVERFLOW at", hex((ea-base)&0xffffffffffffffff))
            ctx = df.CONTEXT(); ctx.ContextFlags = CONTEXT_ALL
            k32.GetThreadContext(pi.hThread, C.byref(ctx))
            print("rsp", hex(ctx.Rsp), "rip", hex(ctx.Rip-base))
            break
        elif ec == 0xC0000005:
            print("AV", hex((ea-base)&0xffffffffffffffff)); break
    elif code == 5:
        print("EXIT", de.u.ExitProcess.dwExitCode); break
    k32.ContinueDebugEvent(de.dwProcessId, de.dwThreadId, 0x10002)
print("hit summary", {hex(k):v for k,v in hits.items()})
k32.TerminateProcess(pi.hProcess, 1)
