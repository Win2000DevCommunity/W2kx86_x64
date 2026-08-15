import ctypes as C
import os, sys, time, struct
from ctypes import wintypes
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
windll = C.windll

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
    windll.kernel32.GetThreadContext(pi.hThread, C.byref(ctx))
    return ctx

def set_ctx(ctx):
    windll.kernel32.SetThreadContext(pi.hThread, C.byref(ctx))

# Known interesting BSS/globals from prior work
GLOBALS = [
    0x800734c0, 0x800734e0, 0x80073500, 0x80070b20,
    0x8006f874, 0x80069800, 0x8006a000,
]

while time.time() - t0 < 10:
    if not k32.WaitForDebugEvent(C.byref(de), 500):
        continue
    st = df.DBG_CONTINUE
    code = de.dwDebugEventCode
    if code == df.CREATE_PROCESS_DEBUG_EVENT:
        base = int(de.u.CreateProcessInfo.lpBaseOfImage)
        # BP on More write call and cmp ax,0x22 and xor
        for rva in (0x2660f, 0x14cf0, 0x14cfa, 0x23dac):
            set_bp(base + rva)
        print("base", hex(base))
    elif code == df.EXCEPTION_DEBUG_EVENT:
        er = de.u.Exception.ExceptionRecord
        ecode = er.ExceptionCode & 0xFFFFFFFF
        addr = int(er.ExceptionAddress)
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
            print("HIT", hex(rva), "rip", hex(hit), "rbp", hex(ctx.Rbp), "rsp", hex(ctx.Rsp))
            print("  rax=%#x rcx=%#x rdx=%#x rsi=%#x rdi=%#x" % (ctx.Rax, ctx.Rcx, ctx.Rdx, ctx.Rsi, ctx.Rdi))
            if rva in (0x2660f, 0x23dac):
                # stack walk
                sp = ctx.Rsp
                print("  stack:")
                for i in range(16):
                    v = u64(read(pi.hProcess, sp + i*8, 8))
                    tag = ""
                    if base <= v < base + 0x100000:
                        tag = " text+%#x" % (v - base)
                    print("    [%+d] %#x%s" % (i*8, v, tag))
                # dump rbp frame locals
                if ctx.Rbp:
                    print("  [rbp+..] frame:")
                    for off in range(-0x40, 0x40, 8):
                        v = u64(read(pi.hProcess, ctx.Rbp + off, 8))
                        note = ""
                        if 0x10000 < (v & 0xffffffff) < 0x7fffffff or (v > 0x80000000 and v < 0x80100000):
                            raw = read(pi.hProcess, v if v > 0x10000 else (v & 0xffffffff), 64)
                            if raw and (raw[1]==0 or b'M' in raw[:20]):
                                try:
                                    s = raw.decode('utf-16le','replace').split('\x00')[0][:60]
                                    if s and any(c.isprintable() for c in s[:10]):
                                        note = " -> " + ascii(s)
                                except Exception:
                                    pass
                        print("    rbp%+d %#x%s" % (off, v, note))
                # cmdline via GetCommandLineW from kernel - PEB
                # also dump known string at rdx
                for label,p in [("rcx",ctx.Rcx),("rdx",ctx.Rdx),("r8",ctx.R8)]:
                    if p > 0x10000:
                        raw=read(pi.hProcess,p,80)
                        try: s=raw.decode('utf-16le','replace').split('\x00')[0][:50]
                        except: s=repr(raw[:40])
                        print(" ",label,ascii(s))
                k32.TerminateProcess(pi.hProcess, 1)
                break
            elif rva == 0x14cf0:
                print("  cmp quote ax=%#x" % (ctx.Rax & 0xffff))
            elif rva == 0x14cfa:
                fl = u32(read(pi.hProcess, ctx.Rsi, 4)) if ctx.Rsi else 0
                print("  xor quote flags=%#x edx=%#x ax=%#x" % (fl, ctx.Rdx & 0xffffffff, ctx.Rax & 0xffff))
            set_ctx(ctx)
            # single step to restore bp
            ctx = get_ctx(); ctx.EFlags |= 0x100; set_ctx(ctx)
            pending = hit
        elif ecode == 0x80000004:
            # rearm all cleared
            for a in list(bps.keys()):
                # only rearm if not still broken
                set_bp(a)
        elif ecode == 0xC0000005:
            print("AV at", hex(addr))
            break
    k32.ContinueDebugEvent(de.dwProcessId, de.dwThreadId, st)

k32.CloseHandle(pi.hProcess); k32.CloseHandle(pi.hThread)
