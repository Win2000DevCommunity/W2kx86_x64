import ctypes as C, sys
from pathlib import Path
sys.path.insert(0, ".")
import dbg_fault as D
D.suppress_fault_ui()
k32 = D.k32
exe = str(Path("build_univ97/cmd_pure.exe").resolve())
si = D.STARTUPINFO(); si.cb = C.sizeof(si)
pi = D.PROCESS_INFORMATION()
cmd = '"' + exe + '" /c echo w2ktest'
assert k32.CreateProcessW(exe, cmd, None, None, False, D.DEBUG_ONLY_THIS_PROCESS, None, str(Path("build_univ97").resolve()), C.byref(si), C.byref(pi))
base=0; de=D.DEBUG_EVENT(); status=D.DBG_CONTINUE; out=[]
while True:
    if not k32.WaitForDebugEvent(C.byref(de), 20000):
        out.append("timeout"); break
    code=de.dwDebugEventCode
    if code==D.CREATE_PROCESS_DEBUG_EVENT:
        base=de.u.CreateProcessInfo.lpBaseOfImage or 0
        if de.u.CreateProcessInfo.hFile: k32.CloseHandle(de.u.CreateProcessInfo.hFile)
    elif code==D.LOAD_DLL_DEBUG_EVENT:
        if de.u.LoadDll.hFile: k32.CloseHandle(de.u.LoadDll.hFile)
    elif code==D.EXCEPTION_DEBUG_EVENT:
        er=de.u.Exception.ExceptionRecord
        if (er.ExceptionCode & 0xFFFFFFFF)==0xC0000005:
            ctx=D.CONTEXT(); ctx.ContextFlags=D.CONTEXT_FULL
            k32.GetThreadContext(pi.hThread, C.byref(ctx))
            out.append("AV rip=%#x fault=%#x RSI=%#x" % ((er.ExceptionAddress or 0)-base, er.ExceptionInformation[1], ctx.Rsi))
            # correct remaps: data_base 0x69000, old_data 0x1c000
            def va(old_rva):
                return 0x69000 + (old_rva - 0x1c000)
            cells=[("c8d8",0x1c8d8),("fbc8",0x1fbc8),("fbe2",0x1fbe2),("21000",0x21000),("21820",0x21820),("22844",0x22844),("faec",0x1faec),("cf44",0x1cf44)]
            for name,orva in cells:
                rva=va(orva)
                out.append("  [%s] file_rva=%#x val=%#x" % (name, rva, D.read_u64(pi.hProcess, base+rva)))
            p=D.read_u64(pi.hProcess, base+va(0x1c8d8))
            if p and p > 0x10000:
                buf=(C.c_char*96)(); n=C.c_size_t()
                if k32.ReadProcessMemory(pi.hProcess, C.c_void_p(p&0xFFFFFFFFFFFFFFFF), buf, 96, C.byref(n)):
                    out.append("cmdline@"+"%#x"%p+" = "+bytes(buf[:n.value]).decode("utf-16-le","replace")[:80])
            # what is at .rsrc start as wchar?
            buf=(C.c_char*32)(); n=C.c_size_t()
            k32.ReadProcessMemory(pi.hProcess, C.c_void_p(base+0x77000), buf, 32, C.byref(n))
            out.append("rsrc_head="+bytes(buf[:n.value]).hex())
            for off in (0x10,0x18):
                out.append("  [rbp%+#x]=%#x" % (off, D.read_u64(pi.hProcess, ctx.Rbp+off)))
            k32.TerminateProcess(pi.hProcess,1); break
    k32.ContinueDebugEvent(de.dwProcessId, de.dwThreadId, status)
Path("_snap_out.txt").write_text("\n".join(out), encoding="utf-8")
print("done", len(out), file=sys.stderr)
