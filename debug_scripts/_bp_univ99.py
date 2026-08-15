"""BP at add9 + More? site; dump args and cmdline buffer."""
import ctypes as C, struct, sys, time
from pathlib import Path
sys.path.insert(0, ".")
import dbg_fault as df
df.suppress_fault_ui()

k32 = df.k32
exe = str(Path("build_univ99/cmd_pure.exe").resolve())
ADD9 = 0x800146F4
MORE = 0x8001474D
SUBL = 0x80014AB4

WATCH = {ADD9: "add9", MORE: "more", SUBL: "sub_len"}

si = df.STARTUPINFO(); si.cb = C.sizeof(si)
pi = df.PROCESS_INFORMATION()
cmd = f'"{exe}" /c echo w2ktest'
ok = k32.CreateProcessW(exe, cmd, None, None, False,
                        df.DEBUG_ONLY_THIS_PROCESS, None,
                        str(Path(exe).parent), C.byref(si), C.byref(pi))
assert ok, k32.GetLastError()

bps = {}
hits = {k: 0 for k in WATCH}
ev = df.DEBUG_EVENT()
t0 = time.time()
done = False
hProcess = None

def set_bp(proc, addr):
    if addr in bps: return
    raw = df.read_process_mem(proc, addr, 1)
    if not raw: return
    bps[addr] = raw[0]
    written = C.c_size_t(0)
    k32.WriteProcessMemory(proc, C.c_void_p(addr), b"\xCC", 1, C.byref(written))
    k32.FlushInstructionCache(proc, C.c_void_p(addr), 1)

def clear_bp(proc, addr):
    if addr not in bps: return
    written = C.c_size_t(0)
    k32.WriteProcessMemory(proc, C.c_void_p(addr), bytes([bps[addr]]), 1, C.byref(written))
    k32.FlushInstructionCache(proc, C.c_void_p(addr), 1)

def dump_mem(proc, addr, n=64):
    if not addr or addr > 0x00007FFFFFFFFFFF:
        return f"<bad {addr:#x}>"
    b = df.read_process_mem(proc, addr, n)
    if not b: return "<unreadable>"
    try:
        u = b.decode("utf-16-le", errors="replace").split("\x00")[0][:100]
    except Exception:
        u = ""
    return f"hex={b[:40].hex()} utf16={u!r}"

def rearm_after_bp(proc, th, bp_addr):
    clear_bp(proc, bp_addr)
    ctx = df.get_thread_context(th)
    ctx.Rip = bp_addr
    ctx.EFlags |= 0x100
    ctx.ContextFlags = df.CONTEXT_FULL
    k32.SetThreadContext(th, C.byref(ctx))
    k32.ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, df.DBG_CONTINUE)
    while True:
        if not k32.WaitForDebugEvent(C.byref(ev), 3000):
            return False
        if ev.dwDebugEventCode == df.EXCEPTION_DEBUG_EVENT:
            er2 = ev.u.Exception.ExceptionRecord
            ec = er2.ExceptionCode & 0xFFFFFFFF
            if ec == 0x80000004:
                ctx2 = df.get_thread_context(th)
                ctx2.EFlags &= ~0x100
                ctx2.ContextFlags = df.CONTEXT_FULL
                k32.SetThreadContext(th, C.byref(ctx2))
                set_bp(proc, bp_addr)
                k32.ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, df.DBG_CONTINUE)
                return True
            if ec == 0x80000003:
                k32.ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, df.DBG_CONTINUE)
                continue
            k32.ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, df.DBG_EXCEPTION_NOT_HANDLED)
        else:
            k32.ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, df.DBG_CONTINUE)

while not done and time.time() - t0 < 20:
    if not k32.WaitForDebugEvent(C.byref(ev), 500):
        continue
    code = ev.dwDebugEventCode
    cont = df.DBG_CONTINUE
    handled = False
    if code == df.CREATE_PROCESS_DEBUG_EVENT:
        hProcess = ev.u.CreateProcessInfo.hProcess
        for a in WATCH:
            set_bp(hProcess, a)
        print(f"[base] ok bps={list(map(hex,bps))}")
    elif code == df.EXCEPTION_DEBUG_EVENT:
        er = ev.u.Exception.ExceptionRecord
        ec = er.ExceptionCode & 0xFFFFFFFF
        addr = er.ExceptionAddress or 0
        if ec == 0x80000003:
            th = k32.OpenThread(0x1F03FF, False, ev.dwThreadId)
            ctx = df.get_thread_context(th)
            bp_addr = addr if addr in bps else (addr - 1 if (addr - 1) in bps else None)
            if bp_addr is not None:
                name = WATCH.get(bp_addr, "?")
                hits[bp_addr] = hits.get(bp_addr, 0) + 1
                n = hits[bp_addr]
                if name == "add9" and n <= 3:
                    print(f"\n[add9 #{n}] RCX={ctx.Rcx:#x} RDX={ctx.Rdx:#x} R8={ctx.R8:#x} R9={ctx.R9:#x}")
                    print(f"  buf@RCX: {dump_mem(hProcess, ctx.Rcx, 128)}")
                    c8b = df.read_process_mem(hProcess, 0x8006A8D8, 8) or b"\0"*8
                    c8 = struct.unpack("<Q", c8b)[0]
                    print(f"  [c8d8]={c8:#x} -> {dump_mem(hProcess, c8, 64)}")
                elif name == "more" and n in (1, 2, 3, 10, 100, 1000, 4090, 4095):
                    print(f"\n[more #{n}] RSI={ctx.Rsi:#x} RDI={ctx.Rdi:#x} RBP={ctx.Rbp:#x} RAX={ctx.Rax:#x}")
                    m8b = df.read_process_mem(hProcess, ctx.Rbp - 8, 8) or b"\0"*8
                    m8 = struct.unpack("<Q", m8b)[0]
                    p10 = struct.unpack("<Q", df.read_process_mem(hProcess, ctx.Rbp+0x10, 8) or b"\0"*8)[0]
                    p18 = struct.unpack("<I", df.read_process_mem(hProcess, ctx.Rbp+0x18, 4) or b"\0"*4)[0]
                    print(f"  [rbp-8]={m8:#x} [rbp+10]={p10:#x} [rbp+18]={p18:#x}")
                    print(f"  start: {dump_mem(hProcess, m8, 80)}")
                    print(f"  rsi:   {dump_mem(hProcess, ctx.Rsi, 32)}")
                elif name == "sub_len" and n <= 8:
                    m8 = struct.unpack("<I", df.read_process_mem(hProcess, ctx.Rbp - 8, 4) or b"\0"*4)[0]
                    print(f"\n[sub_len #{n}] RSI={ctx.Rsi:#x} RDI(pre-mov-done)={ctx.Rdi:#x} [rbp-8]={m8:#x} len_chars={((ctx.Rsi & 0xffffffff)-m8)//2}")
                rearm_after_bp(hProcess, th, bp_addr)
                k32.CloseHandle(th)
                handled = True
            else:
                k32.CloseHandle(th)
        elif ec == 0xC0000005:
            th = k32.OpenThread(0x1F03FF, False, ev.dwThreadId)
            ctx = df.get_thread_context(th)
            print(f"\n[AV] RIP={ctx.Rip:#x} RAX={ctx.Rax:#x} RCX={ctx.Rcx:#x} RSI={ctx.Rsi:#x}")
            print(f"  hits={[ (WATCH[k],v) for k,v in hits.items()]}")
            k32.CloseHandle(th)
            done = True
            cont = df.DBG_EXCEPTION_NOT_HANDLED
    elif code == df.EXIT_PROCESS_DEBUG_EVENT:
        print("exit", ev.u.ExitProcess.dwExitCode)
        done = True
    if not handled:
        k32.ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, cont)

print("DONE hits", [(WATCH[k], v) for k, v in hits.items()])
try:
    k32.TerminateProcess(pi.hProcess, 1)
except Exception:
    pass
