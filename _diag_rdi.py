import ctypes as C
import os, sys, time, struct
sys.path.insert(0, ".")
import dbg_fault as df

df.suppress_fault_ui()
k32 = df.k32
exe = os.path.abspath(r"C:\Users\win2000\Desktop\univ88\cmd_pure.exe")
workdir = os.path.dirname(exe)
cmdline = '"%s" /c echo w2ktest' % exe
si = df.STARTUPINFO(); si.cb = C.sizeof(si)
pi = df.PROCESS_INFORMATION()
assert k32.CreateProcessW(None, C.create_unicode_buffer(cmdline), None, None, False,
    df.DEBUG_PROCESS | df.DEBUG_ONLY_THIS_PROCESS, None, workdir, C.byref(si), C.byref(pi))

def read(proc, addr, n):
    return df.read_process_mem(proc, addr, n) or b""

def u32(b,o=0): return int.from_bytes(b[o:o+4],"little") if len(b)>=o+4 else 0
def u64(b,o=0): return int.from_bytes(b[o:o+8],"little") if len(b)>=o+8 else 0

class CTX(C.Structure):
    _fields_ = [
        ("P1Home", C.c_uint64), ("P2Home", C.c_uint64), ("P3Home", C.c_uint64),
        ("P4Home", C.c_uint64), ("P5Home", C.c_uint64), ("P6Home", C.c_uint64),
        ("ContextFlags", C.c_uint32), ("MxCsr", C.c_uint32),
        ("SegCs", C.c_uint16), ("SegDs", C.c_uint16), ("SegEs", C.c_uint16),
        ("SegFs", C.c_uint16), ("SegGs", C.c_uint16), ("SegSs", C.c_uint16),
        ("EFlags", C.c_uint32),
        ("Dr0", C.c_uint64), ("Dr1", C.c_uint64), ("Dr2", C.c_uint64),
        ("Dr3", C.c_uint64), ("Dr6", C.c_uint64), ("Dr7", C.c_uint64),
        ("Rax", C.c_uint64), ("Rcx", C.c_uint64), ("Rdx", C.c_uint64),
        ("Rbx", C.c_uint64), ("Rsp", C.c_uint64), ("Rbp", C.c_uint64),
        ("Rsi", C.c_uint64), ("Rdi", C.c_uint64),
        ("R8", C.c_uint64), ("R9", C.c_uint64), ("R10", C.c_uint64),
        ("R11", C.c_uint64), ("R12", C.c_uint64), ("R13", C.c_uint64),
        ("R14", C.c_uint64), ("R15", C.c_uint64),
        ("Rip", C.c_uint64),
    ]

bps = {}
de = df.DEBUG_EVENT()
t0 = time.time()
base = 0
hits = 0

def set_bp(addr):
    orig = read(pi.hProcess, addr, 1)
    if not orig: return
    buf = (C.c_char * 1)(0xCC)
    w = C.c_size_t()
    if k32.WriteProcessMemory(pi.hProcess, C.c_uint64(addr), buf, 1, C.byref(w)):
        bps[addr] = orig[0]

def clear_bp(addr):
    if addr not in bps: return
    buf = (C.c_char * 1)(bps[addr])
    w = C.c_size_t()
    k32.WriteProcessMemory(pi.hProcess, C.c_uint64(addr), buf, 1, C.byref(w))

def get_ctx():
    ctx = CTX(); ctx.ContextFlags = 0x10001F
    C.windll.kernel32.GetThreadContext(pi.hThread, C.byref(ctx))
    return ctx

def set_ctx(ctx):
    C.windll.kernel32.SetThreadContext(pi.hThread, C.byref(ctx))

# Find function entry for parse - x86 ~0xb00c area -> pe64
# From map, look for earlier entry
LOAD = 0x14c93  # movzx rax,[rdi]

while time.time() - t0 < 12:
    if not k32.WaitForDebugEvent(C.byref(de), 500):
        continue
    st = df.DBG_CONTINUE
    code = de.dwDebugEventCode
    if code == df.CREATE_PROCESS_DEBUG_EVENT:
        base = int(de.u.CreateProcessInfo.lpBaseOfImage)
        set_bp(base + LOAD)
        set_bp(base + 0x2660f)
        print("base", hex(base))
    elif code == df.EXCEPTION_DEBUG_EVENT:
        er = de.u.Exception.ExceptionRecord
        ecode = er.ExceptionCode & 0xFFFFFFFF
        if ecode == 0x80000003:
            ctx = get_ctx()
            rip = int(ctx.Rip)
            hit = rip if rip in bps else (rip - 1 if (rip - 1) in bps else None)
            if hit is None:
                k32.ContinueDebugEvent(de.dwProcessId, de.dwThreadId, st)
                continue
            clear_bp(hit)
            ctx.Rip = hit
            rva = hit - base
            if rva == LOAD:
                hits += 1
                if hits <= 5 or hits % 50 == 0:
                    raw = read(pi.hProcess, ctx.Rdi, 32)
                    chars = []
                    for i in range(0, min(16,len(raw)), 2):
                        chars.append(raw[i] | (raw[i+1]<<8))
                    # decode as utf16
                    try:
                        s = raw.decode('utf-16le','replace')[:20]
                    except Exception:
                        s = "?"
                    print("LOAD#%d rdi=%#x ax_will=%#x chars=%s str=%r" % (
                        hits, ctx.Rdi, chars[0] if chars else -1,
                        [hex(c) for c in chars[:8]], s))
                    # also dump [rsi] flags and look at buffer base
                    fl = u32(read(pi.hProcess, ctx.Rsi, 4)) if ctx.Rsi else 0
                    print("  rsi=%#x flags=%#x rbp=%#x" % (ctx.Rsi, fl, ctx.Rbp))
                    # dump memory around rdi-16..+16 as hex
                    print("  mem", read(pi.hProcess, ctx.Rdi-8, 40).hex())
                if hits >= 200:
                    print("too many loads, stop")
                    k32.TerminateProcess(pi.hProcess, 1)
                    break
            elif rva == 0x2660f:
                print("MORE after %d loads" % hits)
                raw = read(pi.hProcess, ctx.Rdx, 32)
                print(" more str", raw.decode('utf-16le','replace')[:20])
                k32.TerminateProcess(pi.hProcess, 1)
                break
            set_ctx(ctx)
            ctx = get_ctx(); ctx.EFlags |= 0x100; set_ctx(ctx)
        elif ecode == 0x80000004:
            for a in list(bps.keys()):
                set_bp(a)
        elif ecode == 0xC0000005:
            print("AV")
            break
    k32.ContinueDebugEvent(de.dwProcessId, de.dwThreadId, st)

print("total loads", hits)
k32.CloseHandle(pi.hProcess); k32.CloseHandle(pi.hThread)
