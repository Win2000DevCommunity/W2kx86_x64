import ctypes as C, struct, sys, os
sys.path.insert(0, ".")
import dbg_fault as df
k32 = C.WinDLL("kernel32", use_last_error=True)
df.suppress_fault_ui()
os.chdir("build_univ246")
exe = os.path.abspath("cmd_probe5.exe")
IB = 0x80000000
BPS = {
    IB + 0x489c0: "MATCH",
    IB + 0x18157: "eEcho",
    IB + 0x1d35c: "f4eb",
    IB + 0x262d1: "ultoa",
    IB + 0x2632a: "mb2wc",
    IB + 0x48b34: "fm_jmp",
    IB + 0x2656f: "fm_call",
}
si = df.STARTUPINFO(); si.cb = C.sizeof(si); pi = df.PROCESS_INFORMATION()
cmd = C.create_unicode_buffer('"%s" /c echo w2ktest' % exe)
assert k32.CreateProcessW(exe, cmd, None, None, False, df.DEBUG_ONLY_THIS_PROCESS, None, os.getcwd(), C.byref(si), C.byref(pi))
orig = {}; de = df.DEBUG_EVENT(); hits = 0
def rd(a, n):
    return df.read_process_mem(pi.hProcess, a, n)
while k32.WaitForDebugEvent(C.byref(de), 30000):
    cont = df.DBG_CONTINUE
    if de.dwDebugEventCode == df.CREATE_PROCESS_DEBUG_EVENT:
        for a in BPS:
            b = rd(a, 1)
            if b:
                orig[a] = b[0]
                df.patch_byte(pi.hProcess, a, 0xCC)
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
                hits += 1
                extra = ""
                if bp == IB + 0x2656f:
                    extra = " rbx=%#x rcx=%#x r8=%#x" % (ctx.Rbx, ctx.Rcx, ctx.R8)
                print("HIT %s rip=%#x%s" % (BPS[bp], ctx.Rip, extra))
                if hits > 40:
                    k32.TerminateProcess(pi.hProcess, 1)
                    break
        elif code in (0xC0000005, 0xC0000374):
            ctx = df.get_thread_context(pi.hThread)
            info = er.ExceptionInformation
            print("EXC %#x rip=%#x av=%#x rcx=%#x rbx=%#x" % (code, ctx.Rip, info[1], ctx.Rcx, ctx.Rbx))
            k32.TerminateProcess(pi.hProcess, 1)
            break
        elif code != 0x80000004:
            cont = df.DBG_EXCEPTION_NOT_HANDLED
    elif de.dwDebugEventCode == df.EXIT_PROCESS_DEBUG_EVENT:
        print("exit", hex(de.u.ExitProcess.dwExitCode & 0xffffffff))
        break
    k32.ContinueDebugEvent(de.dwProcessId, de.dwThreadId, cont)
