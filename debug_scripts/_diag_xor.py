import ctypes as C
import os
import sys
import time
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

def u16(b,o=0): return int.from_bytes(b[o:o+2],"little") if len(b)>=o+2 else 0
def u32(b,o=0): return int.from_bytes(b[o:o+4],"little") if len(b)>=o+4 else 0
def u64(b,o=0): return int.from_bytes(b[o:o+8],"little") if len(b)>=o+8 else 0
def read(proc, addr, n): return df.read_process_mem(proc, addr, n) or b""

base = 0
# pe64 sites
XOR = None  # filled after base known: base+0x14cfa
MORE_CALL = None  # base+0x2660f
bps = {}
toggles = []
de = df.DEBUG_EVENT()
t0 = time.time()

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

while time.time() - t0 < 8:
    if not k32.WaitForDebugEvent(C.byref(de), 500):
        continue
    st = df.DBG_CONTINUE
    code = de.dwDebugEventCode
    if code == df.CREATE_PROCESS_DEBUG_EVENT:
        base = int(de.u.CreateProcessInfo.lpBaseOfImage)
        XOR = base + 0x14cfa
        MORE_CALL = base + 0x2660f
        set_bp(XOR)
        set_bp(MORE_CALL)
        print("base", hex(base), "bp xor", hex(XOR), "morecall", hex(MORE_CALL))
    elif code == df.EXCEPTION_DEBUG_EVENT:
        er = de.u.Exception.ExceptionRecord
        ecode = er.ExceptionCode & 0xFFFFFFFF
        addr = int(er.ExceptionAddress)
        if ecode == 0x80000003:
            ctx = df.get_thread_context(pi.hThread)
            rip = int(ctx.Rip)
            hit = rip if rip in bps else (rip - 1 if (rip - 1) in bps else None)
            if hit is None:
                k32.ContinueDebugEvent(de.dwProcessId, de.dwThreadId, st)
                continue
            clear_bp(hit)
            ctx.Rip = hit
            # need SetThreadContext — implement minimal
            # Use dbg_fault get and write via NtSetContext if needed
            CONTEXT_FULL = 0x10001F
            # reuse get_thread_context structure by poking Rip through df if possible
            # Fallback: WriteProcessMemory can't set RIP. Use kernel32 SetThreadContext via df.CONTEXT
            class M64(C.Structure):
                _fields_ = [("Low", C.c_uint64), ("High", C.c_int64)]
            class XMM(C.Structure):
                _fields_ = [("Header", M64 * 2), ("Legacy", M64 * 8),
                            ("Xmm0", M64), ("Xmm1", M64), ("Xmm2", M64), ("Xmm3", M64),
                            ("Xmm4", M64), ("Xmm5", M64), ("Xmm6", M64), ("Xmm7", M64),
                            ("Xmm8", M64), ("Xmm9", M64), ("Xmm10", M64), ("Xmm11", M64),
                            ("Xmm12", M64), ("Xmm13", M64), ("Xmm14", M64), ("Xmm15", M64)]
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
            # Simpler approach: use df.get_thread_context which returns object with .Rip etc
            # and check if it has a setter path — read dbg_fault
            from ctypes import windll
            # get full context
            ctx2 = CTX()
            ctx2.ContextFlags = 0x10001F
            windll.kernel32.GetThreadContext(pi.hThread, C.byref(ctx2))
            ctx2.Rip = hit
            if hit == XOR:
                fl = u32(read(pi.hProcess, ctx2.Rsi, 4)) if ctx2.Rsi else 0
                ch = ctx2.Rax & 0xFFFF
                toggles.append((ch, fl, ctx2.Rdx & 0xFFFFFFFF, ctx2.Rsi))
                print("XOR quote ch=%r flags_before=%#x edx=%#x rsi=%#x" % (chr(ch) if 32 <= ch < 127 else ch, fl, ctx2.Rdx & 0xFFFFFFFF, ctx2.Rsi))
                if len(toggles) >= 12:
                    print("enough toggles")
                    k32.TerminateProcess(pi.hProcess, 1)
                    break
            elif hit == MORE_CALL:
                print("MORE_CALL hit rbp=%#x" % ctx2.Rbp)
                # dump args
                print("  rcx", hex(ctx2.Rcx), "rdx", hex(ctx2.Rdx), "r8", hex(ctx2.R8))
                # try read rdx as utf16 string ptr (buffer?)
                for label, p in [("rcx", ctx2.Rcx), ("rdx", ctx2.Rdx), ("r8", ctx2.R8)]:
                    if 0x10000 < p < 0x800000000000:
                        raw = read(pi.hProcess, p, 80)
                        try:
                            s = raw.decode("utf-16le", "replace").split("\x00")[0][:50]
                        except Exception:
                            s = raw[:40]
                        print(" ", label, ascii(s))
                k32.TerminateProcess(pi.hProcess, 1)
                break
            windll.kernel32.SetThreadContext(pi.hThread, C.byref(ctx2))
            # re-arm after continue: set TF
            ctx2.EFlags |= 0x100
            windll.kernel32.SetThreadContext(pi.hThread, C.byref(ctx2))
            pending = hit
        elif ecode == 0x80000004:
            for a in list(bps.keys()):
                set_bp(a)
        elif ecode == 0xC0000005:
            print("AV")
            break
    k32.ContinueDebugEvent(de.dwProcessId, de.dwThreadId, st)

print("toggles", len(toggles))
for t in toggles:
    print(t)
k32.CloseHandle(pi.hProcess); k32.CloseHandle(pi.hThread)