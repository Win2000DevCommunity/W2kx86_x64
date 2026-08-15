import sys, ctypes as C, struct, os
sys.path.insert(0, ".")
import dbg_fault as df

exe = os.path.abspath(r"build_univ225\cmd_pure.exe")
pe = bytearray(open(exe, "rb").read())
e = struct.unpack_from("<I", pe, 0x3C)[0]
ns = struct.unpack_from("<H", pe, e + 6)[0]
so = struct.unpack_from("<H", pe, e + 20)[0]
sec = e + 24 + so
for i in range(ns):
    o = sec + i * 40
    if pe[o:o+5] == b".text":
        vs, va, rs, rp = struct.unpack_from("<IIII", pe, o + 8)
        break
out = bytearray(pe[rp:rp+rs])
bps = {0x1ea9d: out[0x1ea9d - va], 0x45828: out[0x45828 - va], 0x1d7f4: out[0x1d7f4 - va] if 0x1d7f4-va < len(out) else None}
for rva in list(bps.keys()):
    if bps[rva] is None:
        del bps[rva]
        continue
    out[rva - va] = 0xCC
pe[rp:rp+rs] = out
bp_exe = os.path.abspath(r"build_univ225\cmd_bp_multi.exe")
open(bp_exe, "wb").write(pe)
print("bps", {hex(k): hex(v) for k,v in bps.items()})

k32 = df.k32
si = df.STARTUPINFO(); si.cb = C.sizeof(si)
pi = df.PROCESS_INFORMATION()
cmdline = C.create_unicode_buffer('"%s" /c echo w2ktest' % bp_exe)
assert k32.CreateProcessW(None, cmdline, None, None, False, df.DEBUG_PROCESS, None,
                          os.path.dirname(bp_exe), C.byref(si), C.byref(pi))

class EXCEPTION_RECORD(C.Structure):
    pass
EXCEPTION_RECORD._fields_ = [
    ("ExceptionCode", C.c_ulong), ("ExceptionFlags", C.c_ulong),
    ("ExceptionRecord", C.c_void_p), ("ExceptionAddress", C.c_void_p),
    ("NumberParameters", C.c_ulong), ("ExceptionInformation", C.c_ulonglong * 15),
]
class EXCEPTION_DEBUG_INFO(C.Structure):
    _fields_ = [("ExceptionRecord", EXCEPTION_RECORD), ("dwFirstChance", C.c_ulong)]

ev = df.DEBUG_EVENT()
ib = 0x80000000

def read(h, addr, n):
    buf = (C.c_ubyte * n)()
    br = C.c_size_t()
    if not k32.ReadProcessMemory(h, C.c_void_p(addr), buf, n, C.byref(br)):
        return None
    return bytes(buf)

counts = {r: 0 for r in bps}
try:
    while k32.WaitForDebugEvent(C.byref(ev), 25000):
        if ev.dwDebugEventCode == 1:
            er = C.cast(C.byref(ev.u), C.POINTER(EXCEPTION_DEBUG_INFO)).contents
            ec = er.ExceptionRecord.ExceptionCode
            ea = er.ExceptionRecord.ExceptionAddress or 0
            rva = (ea - ib) & 0xFFFFFFFF
            if ec == 0x80000003 and rva in bps:
                counts[rva] += 1
                ctx = df.CONTEXT()
                ctx.ContextFlags = 0x10001F
                assert k32.GetThreadContext(pi.hProcess and pi.hThread, C.byref(ctx)) if False else k32.GetThreadContext(pi.hThread, C.byref(ctx))
                sticky = struct.unpack_from("<I", read(pi.hProcess, ib+0x5BE00, 4))[0]
                fae0 = struct.unpack_from("<I", read(pi.hProcess, ib+0x5BAE0, 4))[0]
                fbc8 = struct.unpack_from("<I", read(pi.hProcess, ib+0x5BBC8, 4))[0]
                print("BP %05x #%d eax=%08x sticky=%d fae0=%08x fbc8=%08x" % (
                    rva, counts[rva], ctx.Rax & 0xFFFFFFFF, sticky, fae0, fbc8))
                buf = (C.c_ubyte * 1)(bps[rva])
                wr = C.c_size_t()
                k32.WriteProcessMemory(pi.hProcess, C.c_void_p(ea), buf, 1, C.byref(wr))
                ctx.Rip = ea
                k32.SetThreadContext(pi.hThread, C.byref(ctx))
                # re-arm after single step would be better; for now only first few
                if sum(counts.values()) > 12:
                    break
                k32.ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, df.DBG_CONTINUE)
                # re-plant BP
                buf2 = (C.c_ubyte * 1)(0xCC)
                k32.WriteProcessMemory(pi.hProcess, C.c_void_p(ea), buf2, 1, C.byref(wr))
                continue
            if ec == 0xC00000FD:
                print("SO counts", {hex(k): v for k,v in counts.items()})
                fae0 = struct.unpack_from("<I", read(pi.hProcess, ib+0x5BAE0, 4))[0]
                sticky = struct.unpack_from("<I", read(pi.hProcess, ib+0x5BE00, 4))[0]
                print("final fae0=%08x sticky=%d" % (fae0, sticky))
                break
            if ec != 0x80000003:
                print("fault", hex(ec), hex(ea), "counts", counts)
                break
            k32.ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, df.DBG_CONTINUE)
            continue
        elif ev.dwDebugEventCode == 5:
            print("exit", counts)
            break
        k32.ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, df.DBG_CONTINUE)
finally:
    try: k32.TerminateProcess(pi.hProcess, 1)
    except: pass
