"""Live probe: /c flag, fae0 waiter, hang stack. Uses dbg_fault CONTEXT."""
import ctypes as C
from ctypes import wintypes
import struct, time, sys, os
sys.path.insert(0, ".")
import dbg_fault as df

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
df.suppress_fault_ui()

k32 = df.k32
CONTEXT_DEBUG = df.CONTEXT_AMD64 | 0x10
CONTEXT_ALL = df.CONTEXT_FULL | CONTEXT_DEBUG

def rpm(h, addr, n):
    buf = (C.c_ubyte * n)()
    br = C.c_size_t()
    if not k32.ReadProcessMemory(h, C.c_void_p(addr), buf, n, C.byref(br)):
        return None
    return bytes(buf)

def dword(h, addr):
    b = rpm(h, addr, 4)
    return struct.unpack_from("<I", b)[0] if b else None

def dump_flags(h, base, label):
    print(f"=== FLAGS {label} ===", flush=True)
    for name, off in [
        ("/c_58f64", 0x58F64), ("/k_58f60", 0x58F60), ("cf40_58f40", 0x58F40),
        ("fae0", 0x5BAE0), ("fae4", 0x5BAE4), ("fae8", 0x5BAE8),
        ("fb40evt", 0x5BB40), ("sticky", 0x5BE00), ("fbc8", 0x5BBC8),
        ("console_59588", 0x59588),
    ]:
        v = dword(h, base + off)
        print(f"  {name}: {v:#x}" if v is not None else f"  {name}: ?", flush=True)

EXE = os.path.abspath(r"build_univ256\cmd_probe_echo3.exe")
cmd = f'"{EXE}" /c echo w2ktest'
print("CMDLINE", cmd, flush=True)

si = df.STARTUPINFO(); si.cb = C.sizeof(si)
pi = df.PROCESS_INFORMATION()
ok = k32.CreateProcessW(None, C.create_unicode_buffer(cmd), None, None, False,
                        df.DEBUG_PROCESS, None, os.path.dirname(EXE),
                        C.byref(si), C.byref(pi))
if not ok:
    print("CreateProcess FAIL", C.get_last_error()); sys.exit(1)
print("pid", pi.dwProcessId, flush=True)

base = 0
init_bp = True
hits = []
exited = False
av = False
de = df.DEBUG_EVENT()
t0 = time.time()

# DR0=/c store, DR1=waiter cmp, DR2=/c exit-check, DR3=fae0 writer
HW = [0x13ECC, 0x45828, 0x17A8E, 0x1EA9D]
labels = ["/c_store", "waiter", "/c_exitchk", "fae0_wr"]

class EXCEPTION_RECORD(C.Structure):
    pass
EXCEPTION_RECORD._fields_ = [
    ("ExceptionCode", C.c_ulong), ("ExceptionFlags", C.c_ulong),
    ("ExceptionRecord", C.c_void_p), ("ExceptionAddress", C.c_void_p),
    ("NumberParameters", C.c_ulong), ("ExceptionInformation", C.c_ulonglong * 15),
]
class EXCEPTION_DEBUG_INFO(C.Structure):
    _fields_ = [("ExceptionRecord", EXCEPTION_RECORD), ("dwFirstChance", C.c_ulong)]

while time.time() - t0 < 5.0:
    if not k32.WaitForDebugEvent(C.byref(de), 150):
        continue
    code = de.dwDebugEventCode
    if code == 3:  # CREATE_PROCESS
        base = de.u.CreateProcessInfo.lpBaseOfImage or 0
        print("base", hex(base), flush=True)
    elif code == 1:  # EXCEPTION
        er = C.cast(C.byref(de.u), C.POINTER(EXCEPTION_DEBUG_INFO)).contents
        ec = er.ExceptionRecord.ExceptionCode & 0xFFFFFFFF
        ea = er.ExceptionRecord.ExceptionAddress or 0
        if ec == 0x80000003 and init_bp:
            init_bp = False
            ctx = df.CONTEXT(); ctx.ContextFlags = CONTEXT_ALL
            assert k32.GetThreadContext(pi.hThread, C.byref(ctx))
            ctx.Dr0 = base + HW[0]
            ctx.Dr1 = base + HW[1]
            ctx.Dr2 = base + HW[2]
            ctx.Dr3 = base + HW[3]
            ctx.Dr7 = 0x55
            assert k32.SetThreadContext(pi.hThread, C.byref(ctx))
            print("HW armed", [hex(x) for x in HW], flush=True)
            dump_flags(pi.hProcess, base, "init")
        elif ec == 0x80000004:  # SINGLE_STEP
            ctx = df.CONTEXT(); ctx.ContextFlags = CONTEXT_ALL
            assert k32.GetThreadContext(pi.hThread, C.byref(ctx))
            rva = (ctx.Rip - base) & 0xFFFFFFFFFFFFFFFF
            which = [labels[i] for i in range(4) if ctx.Dr6 & (1 << i)]
            print(f"HW {which} rva={rva:#x} rax={ctx.Rax:#x}", flush=True)
            dump_flags(pi.hProcess, base, f"{rva:#x}")
            hits.append((tuple(which), rva, ctx.Rax))
            if "waiter" in which:
                stk = rpm(pi.hProcess, ctx.Rsp, 0x120)
                print("  stack:", flush=True)
                if stk:
                    for off in range(0, 0x120, 8):
                        q = struct.unpack_from("<Q", stk, off)[0]
                        if base <= q < base + 0x100000:
                            print(f"    rsp+{off:#x}={(q-base):#x}", flush=True)
                if sum(1 for w,_,_ in hits if "waiter" in w) >= 1:
                    print("first waiter hit - continue briefly then dump", flush=True)
            ctx.Dr6 = 0
            ctx.EFlags |= 0x10000
            k32.SetThreadContext(pi.hThread, C.byref(ctx))
            # stop after seeing waiter + having waited a bit: handled below via timeout
        elif ec == 0xC0000005:
            rva = (ea - base) & 0xFFFFFFFFFFFFFFFF
            print(f"AV ea={ea:#x} rva={rva:#x}", flush=True)
            dump_flags(pi.hProcess, base, "AV")
            ctx = df.CONTEXT(); ctx.ContextFlags = CONTEXT_ALL
            k32.GetThreadContext(pi.hThread, C.byref(ctx))
            print(f"  rip={ctx.Rip:#x} rsp={ctx.Rsp:#x} rbp={ctx.Rbp:#x}", flush=True)
            av = True
            break
        elif ec not in (0x80000003, 0x80000004):
            print("exc", hex(ec), hex(ea), flush=True)
    elif code == 5:
        print("EXIT_PROCESS", flush=True)
        exited = True
        break
    k32.ContinueDebugEvent(de.dwProcessId, de.dwThreadId, df.DBG_CONTINUE)

# hang dump
ec2 = wintypes.DWORD()
k32.GetExitCodeProcess(pi.hProcess, C.byref(ec2))
print("exitcode", ec2.value, "(259=STILL_ACTIVE)", flush=True)
if ec2.value == 259 and not av:
    print("*** HANG DUMP ***", flush=True)
    k32.SuspendThread(pi.hThread)
    ctx = df.CONTEXT(); ctx.ContextFlags = CONTEXT_ALL
    k32.GetThreadContext(pi.hThread, C.byref(ctx))
    print(f"RIP={ctx.Rip:#x} rva={(ctx.Rip-base)&0xffffffffffffffff:#x}", flush=True)
    print(f"RCX={ctx.Rcx:#x} RDX={ctx.Rdx:#x} R8={ctx.R8:#x} RSP={ctx.Rsp:#x}", flush=True)
    dump_flags(pi.hProcess, base, "HUNG")
    stk = rpm(pi.hProcess, ctx.Rsp, 0x200)
    if stk:
        print("stack main rvas:", flush=True)
        for off in range(0, 0x200, 8):
            q = struct.unpack_from("<Q", stk, off)[0]
            if base <= q < base + 0x200000:
                print(f"  rsp+{off:#x} = {q-base:#x}", flush=True)

print("hits summary:", hits, flush=True)
print("exited", exited, "av", av, flush=True)
try:
    k32.TerminateProcess(pi.hProcess, 1)
except Exception:
    pass
print("KILLED", flush=True)
