import ctypes as C
import struct, sys
from pathlib import Path
sys.path.insert(0, ".")
import dbg_fault as df

df.suppress_fault_ui()
k32 = df.k32

exe = str(Path("build_univ97/cmd_pure.exe").resolve())
si = df.STARTUPINFO(); si.cb = C.sizeof(si)
pi = df.PROCESS_INFORMATION()
cmd = f'"{exe}" /c echo w2ktest'
ok = k32.CreateProcessW(exe, cmd, None, None, False,
                        df.DEBUG_ONLY_THIS_PROCESS, None,
                        str(Path("build_univ97").resolve()),
                        C.byref(si), C.byref(pi))
assert ok

base = 0
# Wait for exception
from ctypes import wintypes
class DEBUG_EVENT(C.Structure):
    pass
# reuse dbg_fault internals by calling its main loop pieces - simpler: patch via running and reading after exception using subprocess to a custom script

# Use df.main pattern - read df for DEBUG_EVENT
import dbg_fault as D
de = D.DEBUG_EVENT()
status = D.DBG_CONTINUE
while True:
    if not k32.WaitForDebugEvent(C.byref(de), 15000):
        print("timeout"); break
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
        if ecode == 0x80000003:
            pass
        elif ecode == 0xC0000005:
            addr = er.ExceptionAddress or 0
            fault = er.ExceptionInformation[1] & 0xFFFFFFFFFFFFFFFF
            ctx = D.CONTEXT(); ctx.ContextFlags = D.CONTEXT_FULL
            k32.GetThreadContext(pi.hThread, C.byref(ctx))
            print(f"AV rip={addr-base:#x} fault={fault:#x}")
            print(f"RAX={ctx.Rax:#x} RCX={ctx.Rcx:#x} RDX={ctx.Rdx:#x} RBX={ctx.Rbx:#x}")
            print(f"RSI={ctx.Rsi:#x} RDI={ctx.Rdi:#x} R8={ctx.R8:#x} R9={ctx.R9:#x}")
            print(f"RBP={ctx.Rbp:#x} RSP={ctx.Rsp:#x}")
            cells = {
                "fbc8": 0x6cbc8, "fbe2": 0x6cbe2, "21000": 0x6e000,
                "c8d8": 0x6abc8, "21820": 0x6e820, "22844": 0x6f844,
                "faec": 0x6caec, "fae4": 0x6cae4, "fae0": 0x6cae0,
            }
            for name, rva in cells.items():
                b = D.read_mem(pi.hProcess, base + rva, 8)
                if len(b) >= 4:
                    v32 = struct.unpack_from("<I", b)[0]
                    v64 = struct.unpack_from("<Q", b)[0] if len(b)>=8 else 0
                    print(f"  [{name}] @{rva:#x} = {v32:#x} (q={v64:#x})")
            # rbp homes
            for off in (0x10, 0x18, 0x20, 0x28, -8, -4):
                b = D.read_mem(pi.hProcess, ctx.Rbp + off, 8)
                if len(b)==8:
                    print(f"  [rbp{off:+#x}] = {struct.unpack('<Q',b)[0]:#x}")
            # peek cmdline if c8d8 looks like ptr
            b = D.read_mem(pi.hProcess, base + 0x6abc8, 8)
            p = struct.unpack_from("<Q", b)[0] if len(b)==8 else 0
            if p:
                s = D.read_mem(pi.hProcess, p, 64)
                print("  cmdline bytes", s[:64])
                try:
                    print("  cmdline utf16", s.decode("utf-16-le", errors="replace")[:40])
                except Exception:
                    pass
            # fbe2 content
            s = D.read_mem(pi.hProcess, base + 0x6cbe2, 32)
            print("  fbe2 content", s.hex(), s.decode("utf-16-le", errors="replace")[:20])
            k32.TerminateProcess(pi.hProcess, 1)
            break
    k32.ContinueDebugEvent(de.dwProcessId, de.dwThreadId, status)
k32.CloseHandle(pi.hProcess); k32.CloseHandle(pi.hThread)
