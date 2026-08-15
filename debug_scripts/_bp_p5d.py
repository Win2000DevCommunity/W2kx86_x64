import ctypes as C, struct, sys, os
sys.path.insert(0, ".")
import dbg_fault as df
k32 = C.WinDLL("kernel32", use_last_error=True)
df.suppress_fault_ui()
os.chdir("build_univ246")
exe = os.path.abspath("cmd_probe5.exe")
IB = 0x80000000
# Break on wrapper entries
BPS = {IB + 0x260a8: "wrap1", IB + 0x260fc: "wrap2", IB + 0x266d0: "printer"}
si = df.STARTUPINFO(); si.cb = C.sizeof(si); pi = df.PROCESS_INFORMATION()
cmd = C.create_unicode_buffer('"%s" /c echo w2ktest' % exe)
assert k32.CreateProcessW(exe, cmd, None, None, False, df.DEBUG_ONLY_THIS_PROCESS, None, os.getcwd(), C.byref(si), C.byref(pi))
orig = {}; de = df.DEBUG_EVENT(); hits = 0; seen = {}
def rd(a, n):
    return df.read_process_mem(pi.hProcess, a, n)
while k32.WaitForDebugEvent(C.byref(de), 20000):
    cont = df.DBG_CONTINUE
    if de.dwDebugEventCode == df.CREATE_PROCESS_DEBUG_EVENT:
        for a in BPS:
            b = rd(a, 1)
            if b:
                orig[a] = b[0]; df.patch_byte(pi.hProcess, a, 0xCC)
        if de.u.CreateProcessInfo.hFile:
            k32.CloseHandle(de.u.CreateProcessInfo.hFile)
    elif de.dwDebugEventCode == df.LOAD_DLL_DEBUG_EVENT:
        if de.u.LoadDll.hFile:
            k32.CloseHandle(de.u.LoadDll.hFile)
    elif de.dwDebugEventCode == df.EXCEPTION_DEBUG_EVENT:
        er = de.u.Exception.ExceptionRecord
        code = er.ExceptionCode & 0xffffffff
        addr = er.ExceptionAddress
        if code == 0x80000003:
            bp = addr if addr in orig else (addr - 1 if addr - 1 in orig else None)
            if bp is not None:
                ctx = df.get_thread_context(pi.hThread)
                df.patch_byte(pi.hProcess, bp, orig[bp])
                ctx.Rip = bp
                ctx.EFlags &= ~0x100
                k32.SetThreadContext(pi.hThread, C.byref(ctx))
                ret = struct.unpack_from("<Q", rd(ctx.Rsp, 8) or b"\0"*8)[0]
                key = (BPS[bp], ctx.Rcx & 0xffffffff, ret)
                seen[key] = seen.get(key, 0) + 1
                hits += 1
                if seen[key] <= 2:
                    print("HIT %s rcx=%#x ret=%#x n=%d" % (BPS[bp], ctx.Rcx, ret, seen[key]))
                # re-arm only for first 30 unique-ish
                if hits < 25:
                    df.patch_byte(pi.hProcess, bp, 0xCC)
                if hits > 80:
                    print("TOP:")
                    for k, v in sorted(seen.items(), key=lambda x: -x[1])[:10]:
                        print(k, v)
                    k32.TerminateProcess(pi.hProcess, 1)
                    break
        elif code in (0xC0000005, 0xC0000374):
            ctx = df.get_thread_context(pi.hThread)
            print("EXC rip=%#x" % ctx.Rip)
            print("TOP:")
            for k, v in sorted(seen.items(), key=lambda x: -x[1])[:10]:
                print(k, v)
            k32.TerminateProcess(pi.hProcess, 1)
            break
        elif code != 0x80000004:
            cont = df.DBG_EXCEPTION_NOT_HANDLED
    elif de.dwDebugEventCode == df.EXIT_PROCESS_DEBUG_EVENT:
        print("exit", hex(de.u.ExitProcess.dwExitCode & 0xffffffff))
        break
    k32.ContinueDebugEvent(de.dwProcessId, de.dwThreadId, cont)
