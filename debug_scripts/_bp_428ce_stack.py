"""Confirm stack imbalance at 0x428CE shared epi after call r12 callee."""
import sys, os
sys.path.insert(0, ".")
import dbg_fault as df
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

k32 = df.k32
df.suppress_fault_ui()
EXE = os.path.abspath(r"build_univ256\cmd_probe_ecx.exe")
IB = 0x80000000
md = Cs(CS_ARCH_X86, CS_MODE_64)

# soft BPs
WATCH = {
    0x4276c: "callee_entry",
    0x427fb: "jmp_to_428ce",   # success path before jmp
    0x428ce: "add_rsp8",
    0x428d2: "pop_rdi",
    0x428d6: "pop_rsi",
    0x428d7: "ret",
    0x18e56: "after_r12",
}

si = df.STARTUPINFO(); si.cb = __import__("ctypes").sizeof(si)
pi = df.PROCESS_INFORMATION()
cmd = __import__("ctypes").create_unicode_buffer(f'"{EXE}" /c echo w2ktest')
assert k32.CreateProcessW(EXE, cmd, None, None, False,
    df.DEBUG_ONLY_THIS_PROCESS, None, os.path.dirname(EXE),
    __import__("ctypes").byref(si), __import__("ctypes").byref(pi))

orig = {}
base = IB
de = df.DEBUG_EVENT()

def dump(ctx, tag):
    print(f"--- {tag} RIP={(ctx.Rip-base):#x} ---")
    print(f"  rax={ctx.Rax:#x} rbx={ctx.Rbx:#x} rsi={ctx.Rsi:#x} rdi={ctx.Rdi:#x}")
    print(f"  rsp={ctx.Rsp:#x} rbp={ctx.Rbp:#x}")
    for off in range(0, 0x30, 8):
        v = df.read_u64(pi.hProcess, ctx.Rsp+off)
        t = f" code={(v-base):#x}" if base <= v < base+0x80000 else ""
        print(f"  [rsp+{off:#x}]={v:#x}{t}")

while k32.WaitForDebugEvent(__import__("ctypes").byref(de), 20000):
    cont = df.DBG_CONTINUE
    if de.dwDebugEventCode == df.CREATE_PROCESS_DEBUG_EVENT:
        base = de.u.CreateProcessInfo.lpBaseOfImage or IB
        for rva, name in WATCH.items():
            a = base + rva
            b = df.read_process_mem(pi.hProcess, a, 1)
            orig[a] = b[0]
            df.patch_byte(pi.hProcess, a, 0xCC)
            print(f"bp {name} @ {rva:#x}")
        if de.u.CreateProcessInfo.hFile:
            k32.CloseHandle(de.u.CreateProcessInfo.hFile)
    elif de.dwDebugEventCode == df.EXCEPTION_DEBUG_EVENT:
        er = de.u.Exception.ExceptionRecord
        code = er.ExceptionCode & 0xFFFFFFFF
        addr = int(er.ExceptionAddress or 0)
        if code == 0x80000003:
            bp = addr if addr in orig else (addr-1 if addr-1 in orig else None)
            if bp is None and addr < 0x10000:
                pass
            elif bp is not None:
                ctx = df.get_thread_context(pi.hThread)
                df.patch_byte(pi.hProcess, bp, orig[bp])
                ctx.Rip = bp
                name = WATCH.get(bp-base, "?")
                dump(ctx, name)
                # one-shot for most; keep ret and add for clarity
                k32.SetThreadContext(pi.hThread, __import__("ctypes").byref(ctx))
                if name == "ret":
                    # about to ret — show target
                    tgt = df.read_u64(pi.hProcess, ctx.Rsp)
                    print(f"  *** RET TARGET = {tgt:#x}  "
                          f"is_code={base<=tgt<base+0x80000}  rsi={ctx.Rsi:#x}")
                if name == "after_r12":
                    print("returned OK — unexpected")
                    k32.TerminateProcess(pi.hProcess, 0)
                    break
            else:
                cont = df.DBG_EXCEPTION_NOT_HANDLED
        elif code == 0xC0000005:
            ctx = df.get_thread_context(pi.hThread)
            dump(ctx, "AV")
            print(f"AV execute={er.ExceptionInformation[0]==8} addr={addr:#x}")
            k32.TerminateProcess(pi.hProcess, 1)
            break
        else:
            cont = df.DBG_EXCEPTION_NOT_HANDLED
    elif de.dwDebugEventCode == df.EXIT_PROCESS_DEBUG_EVENT:
        print("exit")
        break
    k32.ContinueDebugEvent(de.dwProcessId, de.dwThreadId, cont)
