import ctypes as C, struct, sys, os
sys.path.insert(0, ".")
import dbg_fault as df
k32 = C.WinDLL("kernel32", use_last_error=True)
df.suppress_fault_ui()
os.chdir("build_univ246")
exe = os.path.abspath("cmd_probe5.exe")
IB = 0x80000000
si = df.STARTUPINFO(); si.cb = C.sizeof(si); pi = df.PROCESS_INFORMATION()
cmd = C.create_unicode_buffer('"%s" /c echo w2ktest' % exe)
assert k32.CreateProcessW(exe, cmd, None, None, False, df.DEBUG_ONLY_THIS_PROCESS, None, os.getcwd(), C.byref(si), C.byref(pi))
de = df.DEBUG_EVENT()
def rd(a, n):
    return df.read_process_mem(pi.hProcess, a, n)
while k32.WaitForDebugEvent(C.byref(de), 30000):
    cont = df.DBG_CONTINUE
    if de.dwDebugEventCode == df.CREATE_PROCESS_DEBUG_EVENT:
        if de.u.CreateProcessInfo.hFile:
            k32.CloseHandle(de.u.CreateProcessInfo.hFile)
    elif de.dwDebugEventCode == df.LOAD_DLL_DEBUG_EVENT:
        if de.u.LoadDll.hFile:
            k32.CloseHandle(de.u.LoadDll.hFile)
    elif de.dwDebugEventCode == df.EXCEPTION_DEBUG_EVENT:
        er = de.u.Exception.ExceptionRecord
        code = er.ExceptionCode & 0xffffffff
        if code in (0xC0000005, 0xC0000374):
            ctx = df.get_thread_context(pi.hThread)
            info = er.ExceptionInformation
            print("EXC %#x rip=%#x av=%#x type=%d" % (code, ctx.Rip, info[1], info[0]))
            print(" rax=%#x rcx=%#x rdx=%#x rbx=%#x rsp=%#x rbp=%#x" % (ctx.Rax, ctx.Rcx, ctx.Rdx, ctx.Rbx, ctx.Rsp, ctx.Rbp))
            print(" rsi=%#x rdi=%#x r8=%#x r9=%#x" % (ctx.Rsi, ctx.Rdi, ctx.R8, ctx.R9))
            st = rd(ctx.Rsp, 0x80)
            if st:
                for i in range(0, 0x80, 8):
                    v = struct.unpack_from("<Q", st, i)[0]
                    mark = ""
                    if IB <= v < IB + 0x90000:
                        mark = " TEXT"
                    print("  [rsp+%#x]=%#x%s" % (i, v, mark))
            k32.TerminateProcess(pi.hProcess, 1)
            break
        elif code == 0x80000003:
            cont = df.DBG_CONTINUE
        elif code != 0x80000004:
            cont = df.DBG_EXCEPTION_NOT_HANDLED
    elif de.dwDebugEventCode == df.EXIT_PROCESS_DEBUG_EVENT:
        print("exit", hex(de.u.ExitProcess.dwExitCode & 0xffffffff))
        break
    k32.ContinueDebugEvent(de.dwProcessId, de.dwThreadId, cont)
