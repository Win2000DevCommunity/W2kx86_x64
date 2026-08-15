"""One-shot BPs; handle single-step; dump echo path."""
import ctypes as C, struct, sys, os
from ctypes import wintypes
sys.path.insert(0, ".")
import dbg_fault as df

k32 = C.WinDLL("kernel32", use_last_error=True)
df.suppress_fault_ui()
os.chdir("build_univ229")
exe = os.path.abspath("cmd_diam.exe")
IB = 0x80000000
# one-shot interesting sites
NAMES = {
    IB+0x189c4: "echo",
    IB+0xc468: "c468",
    IB+0xc514: "c514",
    IB+0x28858: "lensum",
    IB+0x288d7: "lensum_sum",
    IB+0x288ee: "lensum_alloc",
    IB+0xc546: "c514_alloc",
    IB+0xc597: "c514_d08c",
    IB+0x1eb78: "ffa2",
    IB+0x1e0d4: "fb2b",
}

si = df.STARTUPINFO(); si.cb = C.sizeof(si)
pi = df.PROCESS_INFORMATION()
cmd = C.create_unicode_buffer(f'"{exe}" /c echo w2ktest')
assert k32.CreateProcessW(exe, cmd, None, None, False,
    df.DEBUG_ONLY_THIS_PROCESS, None, os.getcwd(), C.byref(si), C.byref(pi))

orig = {}
pending_rearm = None
hits = []
de = df.DEBUG_EVENT()

def ru32(a):
    b = df.read_process_mem(pi.hProcess, a, 4)
    return struct.unpack("<I", b)[0] if b and len(b)==4 else None
def ru64(a):
    b = df.read_process_mem(pi.hProcess, a, 8)
    return struct.unpack("<Q", b)[0] if b and len(b)==8 else None
def rw(a,n=40):
    b = df.read_process_mem(pi.hProcess, a, n*2)
    if not b: return None
    return b.decode("utf-16-le","replace").split("\0")[0][:50]

while k32.WaitForDebugEvent(C.byref(de), 20000):
    cont = df.DBG_CONTINUE
    if de.dwDebugEventCode == df.CREATE_PROCESS_DEBUG_EVENT:
        print("base", hex(de.u.CreateProcessInfo.lpBaseOfImage))
        for va, nm in NAMES.items():
            b = df.read_process_mem(pi.hProcess, va, 1)
            if not b: print("fail", nm); continue
            orig[va] = b[0]
            df.patch_byte(pi.hProcess, va, 0xCC)
        if de.u.CreateProcessInfo.hFile:
            k32.CloseHandle(de.u.CreateProcessInfo.hFile)
    elif de.dwDebugEventCode == df.EXCEPTION_DEBUG_EVENT:
        er = de.u.Exception.ExceptionRecord
        code = er.ExceptionCode & 0xFFFFFFFF
        addr = er.ExceptionAddress
        if code == 0x80000003:
            bp = addr if addr in orig else (addr-1 if (addr-1) in orig else None)
            if bp is None:
                # system bp
                pass
            else:
                ctx = df.get_thread_context(pi.hThread)
                df.patch_byte(pi.hProcess, bp, orig[bp])
                ctx.Rip = bp
                # arm TF to re-set BP after insn if we want multi; for one-shot leave off
                ctx.EFlags &= ~0x100
                k32.SetThreadContext(pi.hThread, C.byref(ctx))
                nm = NAMES[bp]
                rec = dict(name=nm, rcx=hex(ctx.Rcx), rdx=hex(ctx.Rdx), rax=hex(ctx.Rax),
                           rsi=hex(ctx.Rsi), rdi=hex(ctx.Rdi), rbx=hex(ctx.Rbx))
                node = None
                if nm in ("echo","c468","c514","lensum","ffa2","fb2b"):
                    node = ctx.Rcx
                if nm == "lensum_sum":
                    rec["edi"] = hex(ctx.Rdi & 0xffffffff)
                    rec["eax"] = hex(ctx.Rax & 0xffffffff)
                    node = ctx.Rsi
                if nm in ("lensum_alloc","c514_alloc"):
                    rec["size"] = hex(ctx.Rcx)
                if node:
                    d38, d3c = ru32(node+0x38), ru32(node+0x3c)
                    rec["node"]=hex(node); rec["d38"]=hex(d38) if d38 is not None else None
                    rec["d3c"]=hex(d3c) if d3c is not None else None
                    if d38 and d38>0x10000: rec["s38"]=rw(d38)
                    if d3c and d3c>0x10000: rec["s3c"]=rw(d3c)
                    elif d3c is not None: rec["s3c_note"]="small_or_null"
                hits.append(rec); print(rec)
        elif code == 0x80000004:
            # single step
            if pending_rearm:
                df.patch_byte(pi.hProcess, pending_rearm, 0xCC)
                pending_rearm = None
        elif code in (0xC0000005, 0xC0000374):
            ctx = df.get_thread_context(pi.hThread)
            print("FAULT", hex(code), "rip", hex(ctx.Rip), "rcx", hex(ctx.Rcx),
                  "rdx", hex(ctx.Rdx), "r8", hex(ctx.R8), "rbp", hex(ctx.Rbp), "rsp", hex(ctx.Rsp))
            # stack ret addrs
            stk = df.read_process_mem(pi.hProcess, ctx.Rsp, 0x40)
            if stk:
                qs = struct.unpack("<8Q", stk)
                print("stack", [hex(x) for x in qs])
            print("--- hits ---")
            for h in hits: print(h)
            k32.TerminateProcess(pi.hProcess, 1)
            break
        else:
            cont = df.DBG_EXCEPTION_NOT_HANDLED
    elif de.dwDebugEventCode == df.EXIT_PROCESS_DEBUG_EVENT:
        print("exit", hex(de.u.ExitProcess.dwExitCode & 0xffffffff))
        break
    k32.ContinueDebugEvent(de.dwProcessId, de.dwThreadId, cont)

print("done hits", len(hits))
