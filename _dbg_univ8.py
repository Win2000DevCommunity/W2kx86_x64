import struct, pathlib, sys, os, ctypes
from ctypes import wintypes
os.environ["PURE"]="1"
sys.path.insert(0, ".")
import dbg_fault as df

# Use dbg with breakpoints on 1d7f4 (echo dispatch) and 17d72
exe = str(pathlib.Path("build_univ227/cmd_univ8.exe").resolve())

# Quick: dump cmdline buffer and fae0/fbc8 at crash via modifying approach -
# run under debugger stopping at first AV and dump .data slots

k32 = ctypes.WinDLL("kernel32", use_last_error=True)
dbg = df

# Reuse df.main but patch to dump data on exception - simpler manual script
import subprocess
# Actually use a small debug loop
from dbg_fault import *

df.suppress_fault_ui()
si = STARTUPINFO()
si.cb = ctypes.sizeof(si)
pi = PROCESS_INFORMATION()
cmd = f"\"{exe}\" /c echo w2ktest"
if not k32.CreateProcessW(None, cmd, None, None, False, DEBUG_ONLY_THIS_PROCESS, None, str(pathlib.Path(exe).parent), ctypes.byref(si), ctypes.byref(pi)):
    raise OSError("CreateProcess")

base = None
ev = DEBUG_EVENT()
while k32.WaitForDebugEvent(ctypes.byref(ev), 15000):
    if ev.dwDebugEventCode == CREATE_PROCESS_DEBUG_EVENT:
        base = ev.u.CreateProcessInfo.lpBaseOfImage
        print("base", hex(base or 0))
    elif ev.dwDebugEventCode == EXCEPTION_DEBUG_EVENT:
        code = ev.u.Exception.ExceptionRecord.ExceptionCode
        addr = ev.u.Exception.ExceptionRecord.ExceptionAddress
        if code == 0x80000003:  # breakpoint
            k32.ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, DBG_CONTINUE)
            continue
        if ev.u.Exception.dwFirstChance and code in (0xC0000005, 0xC000001D, 0xC00000FD):
            ctx = CONTEXT()
            ctx.ContextFlags = CONTEXT_FULL
            ht = ev.u.Exception.ExceptionRecord  # need thread handle
            # get thread
            th = k32.OpenThread(0x1F03FF, False, ev.dwThreadId)
            get_thread_context(th, ctx)
            print("EX", hex(code), "rip", hex(ctx.Rip), "rcx", hex(ctx.Rcx), "rax", hex(ctx.Rax), "rbx", hex(ctx.Rbx))
            # dump fae0, fbc8, c8d8
            def ru64(a):
                b = (ctypes.c_uint64*1)()
                n = ctypes.c_size_t()
                k32.ReadProcessMemory(pi.hProcess, ctypes.c_uint64(a), b, 8, ctypes.byref(n))
                return b[0]
            def ru32(a):
                return ru64(a) & 0xffffffff
            ib = base or 0x80000000
            for name,off in [("c8d8",0x588d8),("fae0",0x5bae0),("fbc8",0x5bbc8),("fbe2",0x5bbe2)]:
                v = ru32(ib+off)
                print(f"  {name}={hex(v)}")
            # dump wchar at c8d8 ptr
            p = ru32(ib+0x588d8)
            if p:
                buf = (ctypes.c_char * 64)()
                k32.ReadProcessMemory(pi.hProcess, ctypes.c_uint64(p), buf, 64, ctypes.byref(ctypes.c_size_t()))
                print("  buf", bytes(buf))
            # stack rets
            for off in range(0, 0x40, 8):
                v = ru64(ctx.Rsp+off)
                if 0x80000000 <= v < 0x80100000:
                    print(f"  rsp+{off:x}={hex(v)} rva={hex(v-ib)}")
            k32.CloseHandle(th)
            break
    if not k32.ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, DBG_CONTINUE):
        break
k32.TerminateProcess(pi.hProcess, 0)
