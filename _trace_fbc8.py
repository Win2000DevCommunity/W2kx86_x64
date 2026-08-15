import ctypes as C, struct, sys, time
from pathlib import Path
sys.path.insert(0, ".")
import dbg_fault as df
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
df.suppress_fault_ui()
k32 = df.k32
exe = str(Path("build_univ101/cmd_pure.exe").resolve())
m = {int(a[0],16):int(a[1],16) for ln in Path("build_univ101/rva.txt").read_text().splitlines() if len(a:=ln.split())>=2}
ADD9 = 0x80000000 + m[0xADD9]
FBC8 = 0x8006DBC8
BASE = 0x80000000
SIZE = 0xA0000
si = df.STARTUPINFO(); si.cb = C.sizeof(si)
pi = df.PROCESS_INFORMATION()
ok = k32.CreateProcessW(exe, f'"{exe}" /c echo w2ktest', None, None, False,
                        df.DEBUG_ONLY_THIS_PROCESS, None, str(Path(exe).parent),
                        C.byref(si), C.byref(pi))
assert ok
ev = df.DEBUG_EVENT()
hP = None
t0 = time.time()
ring = []
md = Cs(CS_ARCH_X86, CS_MODE_64)
fixed = False
orig = None
tracing = False
steps = 0

def in_main(rip):
    return BASE <= rip < BASE + SIZE

while time.time() - t0 < 20:
    if not k32.WaitForDebugEvent(C.byref(ev), 500):
        continue
    code = ev.dwDebugEventCode
    cont = df.DBG_CONTINUE
    if code == df.CREATE_PROCESS_DEBUG_EVENT:
        hP = ev.u.CreateProcessInfo.hProcess
        orig = df.read_process_mem(hP, ADD9, 1)[0]
        wr = C.c_size_t(0)
        k32.WriteProcessMemory(hP, C.c_void_p(ADD9), b"\xCC", 1, C.byref(wr))
    elif code == df.EXCEPTION_DEBUG_EVENT:
        er = ev.u.Exception.ExceptionRecord
        ec = er.ExceptionCode & 0xFFFFFFFF
        addr = er.ExceptionAddress or 0
        th = k32.OpenThread(0x1F03FF, False, ev.dwThreadId)
        ctx = df.get_thread_context(th)
        if ec == 0x80000003 and addr == ADD9 and not fixed:
            if ctx.Rcx:
                wr = C.c_size_t(0)
                ptr = ctx.Rcx & 0xFFFFFFFF
                k32.WriteProcessMemory(hP, C.c_void_p(FBC8), struct.pack("<I", ptr), 4, C.byref(wr))
                print(f"fixed fbc8={ptr:#x}")
            fixed = True
            wr = C.c_size_t(0)
            k32.WriteProcessMemory(hP, C.c_void_p(ADD9), bytes([orig]), 1, C.byref(wr))
            ctx.Rip = ADD9
            ctx.EFlags |= 0x100
            ctx.ContextFlags = df.CONTEXT_FULL
            k32.SetThreadContext(th, C.byref(ctx))
            tracing = True
            k32.CloseHandle(th)
            k32.ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, cont)
            continue
        if ec == 0x80000004 and tracing:
            steps += 1
            rip = ctx.Rip
            if in_main(rip):
                raw = df.read_process_mem(hP, rip, 15) or b""
                txt = "?"
                for insn in md.disasm(raw, rip):
                    txt = f"{insn.mnemonic} {insn.op_str}"
                    break
                ring.append((rip - BASE, ctx.Rsp, ctx.Rax, ctx.Rcx, ctx.Rdx, ctx.Rbx, ctx.Rsi, ctx.Rdi, txt))
                if len(ring) > 40:
                    ring.pop(0)
                ctx.EFlags |= 0x100
                ctx.ContextFlags = df.CONTEXT_FULL
                k32.SetThreadContext(th, C.byref(ctx))
            else:
                # step-over: BP on return
                ret = struct.unpack("<Q", df.read_process_mem(hP, ctx.Rsp, 8) or b"\0"*8)[0]
                if in_main(ret):
                    # plant int3
                    b = df.read_process_mem(hP, ret, 1)
                    if b:
                        # store and plant - keep simple: just keep TF off and hope we return
                        pass
                ctx.EFlags &= ~0x100
                # plant one-shot at ret if in main
                if in_main(ret):
                    rb = df.read_process_mem(hP, ret, 1)
                    if rb and not hasattr(sys, '_retbp'):
                        sys._retbp = (ret, rb[0])
                        wr = C.c_size_t(0)
                        k32.WriteProcessMemory(hP, C.c_void_p(ret), b"\xCC", 1, C.byref(wr))
                ctx.ContextFlags = df.CONTEXT_FULL
                k32.SetThreadContext(th, C.byref(ctx))
            k32.CloseHandle(th)
            k32.ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, cont)
            continue
        if ec == 0x80000003 and tracing and hasattr(sys, '_retbp') and addr == sys._retbp[0]:
            ret, ob = sys._retbp
            wr = C.c_size_t(0)
            k32.WriteProcessMemory(hP, C.c_void_p(ret), bytes([ob]), 1, C.byref(wr))
            del sys._retbp
            ctx.Rip = ret
            ctx.EFlags |= 0x100
            ctx.ContextFlags = df.CONTEXT_FULL
            k32.SetThreadContext(th, C.byref(ctx))
            k32.CloseHandle(th)
            k32.ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, cont)
            continue
        if ec == 0xC0000005:
            print(f"AV RIP={ctx.Rip:#x} steps={steps}")
            print(f"RAX={ctx.Rax:#x} RCX={ctx.Rcx:#x} RDX={ctx.Rdx:#x} RBX={ctx.Rbx:#x}")
            print(f"RSP={ctx.Rsp:#x} RBP={ctx.Rbp:#x} RSI={ctx.Rsi:#x} RDI={ctx.Rdi:#x}")
            print("--- last main ---")
            for rva, sp, ax, cx, dx, bx, si, di, txt in ring[-30:]:
                print(f"  +{rva:05x} rsp={sp:x} rax={ax:x} rcx={cx:x} rbx={bx:x} rsi={si:x} rdi={di:x}  {txt}")
            k32.CloseHandle(th)
            break
        k32.CloseHandle(th)
    elif code == df.EXIT_PROCESS_DEBUG_EVENT:
        print("exit", ev.u.ExitProcess.dwExitCode)
        break
    k32.ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, cont)
try:
    k32.TerminateProcess(pi.hProcess, 1)
except Exception:
    pass
