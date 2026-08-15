import ctypes as C, struct, sys
from pathlib import Path
sys.path.insert(0, ".")
import dbg_fault as D
D.suppress_fault_ui()
k32 = D.k32
exe = str(Path("build_univ97/cmd_pure.exe").resolve())
si = D.STARTUPINFO(); si.cb = C.sizeof(si)
pi = D.PROCESS_INFORMATION()
cmd = f'"{exe}" /c echo w2ktest'
assert k32.CreateProcessW(exe, cmd, None, None, False, D.DEBUG_ONLY_THIS_PROCESS, None, str(Path("build_univ97").resolve()), C.byref(si), C.byref(pi))
base = 0
de = D.DEBUG_EVENT()
status = D.DBG_CONTINUE
while True:
    if not k32.WaitForDebugEvent(C.byref(de), 20000):
        print("timeout"); break
    code = de.dwDebugEventCode
    if code == D.CREATE_PROCESS_DEBUG_EVENT:
        base = de.u.CreateProcessInfo.lpBaseOfImage or 0
        if de.u.CreateProcessInfo.hFile: k32.CloseHandle(de.u.CreateProcessInfo.hFile)
    elif code == D.LOAD_DLL_DEBUG_EVENT:
        if de.u.LoadDll.hFile: k32.CloseHandle(de.u.LoadDll.hFile)
    elif code == D.EXCEPTION_DEBUG_EVENT:
        er = de.u.Exception.ExceptionRecord
        ecode = er.ExceptionCode & 0xFFFFFFFF
        if ecode == 0xC0000005:
            ctx = D.CONTEXT(); ctx.ContextFlags = D.CONTEXT_FULL
            k32.GetThreadContext(pi.hThread, C.byref(ctx))
            print(f"AV rip={(er.ExceptionAddress or 0)-base:#x} fault={er.ExceptionInformation[1]:#x}")
            print(f"RAX={ctx.Rax:#x} RSI={ctx.Rsi:#x} RDI={ctx.Rdi:#x} RBP={ctx.Rbp:#x}")
            cells = [("fbc8",0x6cbc8),("fbe2",0x6cbe2),("21000",0x6e000),("c8d8",0x6abc8),("21820",0x6e820),("22844",0x6f844),("faec",0x6caec)]
            for name,rva in cells:
                v = D.read_u64(pi.hProcess, base+rva)
                print(f"  [{name}] = {v:#x}")
            for off in (0x10,0x18,0x20,0x28,-8):
                v = D.read_u64(pi.hProcess, ctx.Rbp+off)
                print(f"  [rbp{off:+#x}] = {v:#x}")
            p = D.read_u64(pi.hProcess, base+0x6abc8)
            if p:
                # read wchar string
                buf = (C.c_char * 80)()
                n=C.c_size_t()
                k32.ReadProcessMemory(pi.hProcess, C.c_void_p(p), buf, 80, C.byref(n))
                raw=bytes(buf[:n.value])
                print("cmdline", raw.decode("utf-16-le","replace")[:60])
            # fbe2 wchar
            buf = (C.c_char * 64)()
            n=C.c_size_t()
            k32.ReadProcessMemory(pi.hProcess, C.c_void_p(base+0x6cbe2), buf, 64, C.byref(n))
            print("fbe2", bytes(buf[:n.value]).decode("utf-16-le","replace")[:40])
            k32.TerminateProcess(pi.hProcess,1); break
    k32.ContinueDebugEvent(de.dwProcessId, de.dwThreadId, status)
