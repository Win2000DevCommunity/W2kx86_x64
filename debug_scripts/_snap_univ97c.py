import ctypes as C
import sys
from pathlib import Path

sys.path.insert(0, ".")
import dbg_fault as D

D.suppress_fault_ui()
k32 = D.k32
exe = str(Path("build_univ97/cmd_pure.exe").resolve())
si = D.STARTUPINFO()
si.cb = C.sizeof(si)
pi = D.PROCESS_INFORMATION()
cmd = '"' + exe + '" /c echo w2ktest'
ok = k32.CreateProcessW(
    exe, cmd, None, None, False,
    D.DEBUG_ONLY_THIS_PROCESS,
    None, str(Path("build_univ97").resolve()),
    C.byref(si), C.byref(pi),
)
assert ok, k32.GetLastError()

base = 0
de = D.DEBUG_EVENT()
status = D.DBG_CONTINUE
out = []
while True:
    if not k32.WaitForDebugEvent(C.byref(de), 20000):
        out.append("timeout")
        break
    code = de.dwDebugEventCode
    if code == D.CREATE_PROCESS_DEBUG_EVENT:
        base = de.u.CreateProcessInfo.lpBaseOfImage or 0
        if de.u.CreateProcessInfo.hFile:
            k32.CloseHandle(de.u.CreateProcessInfo.hFile)
    elif code == D.LOAD_DLL_DEBUG_EVENT:
        if de.u.LoadDll.hFile:
            k32.CloseHandle(de.u.LoadDll.hFile)
    elif code == D.EXCEPTION_DEBUG_EVENT:
        er = de.u.Exception.ExceptionRecord
        ecode = er.ExceptionCode & 0xFFFFFFFF
        if ecode == 0xC0000005:
            ctx = D.CONTEXT()
            ctx.ContextFlags = D.CONTEXT_FULL
            k32.GetThreadContext(pi.hThread, C.byref(ctx))
            out.append("AV rip=%#x fault=%#x" % ((er.ExceptionAddress or 0) - base, er.ExceptionInformation[1]))
            out.append("Regs RAX=%#x RSI=%#x RDI=%#x RBP=%#x RCX=%#x RDX=%#x" % (ctx.Rax, ctx.Rsi, ctx.Rdi, ctx.Rbp, ctx.Rcx, ctx.Rdx))
            for name, rva in [("fbc8", 0x6CBC8), ("21000", 0x6E000), ("c8d8", 0x6ABC8), ("21820", 0x6E820), ("22844", 0x6F844), ("faec", 0x6CAEC)]:
                out.append("  [%s]=%#x" % (name, D.read_u64(pi.hProcess, base + rva)))
            for off in (0x10, 0x18, 0x20, 0x28, -8):
                out.append("  [rbp%+#x]=%#x" % (off, D.read_u64(pi.hProcess, ctx.Rbp + off)))
            p = D.read_u64(pi.hProcess, base + 0x6ABC8)
            if p:
                buf = (C.c_char * 80)()
                n = C.c_size_t()
                k32.ReadProcessMemory(pi.hProcess, C.c_void_p(p), buf, 80, C.byref(n))
                out.append("cmdline=" + bytes(buf[:n.value]).decode("utf-16-le", "replace")[:80])
            buf = (C.c_char * 64)()
            n = C.c_size_t()
            k32.ReadProcessMemory(pi.hProcess, C.c_void_p(base + 0x6CBE2), buf, 64, C.byref(n))
            out.append("fbe2=" + bytes(buf[:n.value]).decode("utf-16-le", "replace")[:40])
            k32.TerminateProcess(pi.hProcess, 1)
            break
    k32.ContinueDebugEvent(de.dwProcessId, de.dwThreadId, status)

Path("_snap_out.txt").write_text("\n".join(out), encoding="utf-8")
print("wrote", len(out), "lines", file=sys.stderr)
