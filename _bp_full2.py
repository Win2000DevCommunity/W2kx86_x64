import sys, ctypes as C, struct, os
from ctypes import wintypes
sys.path.insert(0, ".")
import dbg_fault as df

exe = os.path.abspath(r"build_univ228\full.exe")
pe = bytearray(open(exe, "rb").read())
e = struct.unpack_from("<I", pe, 0x3C)[0]
ns = struct.unpack_from("<H", pe, e+6)[0]
so = struct.unpack_from("<H", pe, e+20)[0]
sec = e+24+so
ib = struct.unpack_from("<Q", pe, e+24+24)[0]
for i in range(ns):
    o = sec+i*40
    if pe[o:o+5] == b".text":
        vs,va,rs,rp = struct.unpack_from("<IIII", pe, o+8); break
out = bytearray(pe[rp:rp+rs])
bps = {}
watch = [0x3624d, 0x1e62c, 0x39892, 0x39895, 0x1d4f4, 0x1d534, 0x1d574, 0x1d5b4,
         0x1d5dd, 0x1d603, 0x1d61a, 0x1e2b4, 0x1d7f4, 0x1ea3c, 0x1d35c, 0x1e64a]
for rva in watch:
    if 0 <= rva-va < len(out):
        bps[rva] = out[rva-va]
        out[rva-va] = 0xCC
pe[rp:rp+rs] = out
bp_exe = os.path.abspath(r"build_univ228\full_bp.exe")
open(bp_exe, "wb").write(pe)

k32 = df.k32
k32.OpenThread.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
k32.OpenThread.restype = wintypes.HANDLE

si = df.STARTUPINFO(); si.cb = C.sizeof(si)
pi = df.PROCESS_INFORMATION()
cmdline = C.create_unicode_buffer(f'"{bp_exe}" /c echo w2ktest')
ok = k32.CreateProcessW(None, cmdline, None, None, False,
                        df.DEBUG_ONLY_THIS_PROCESS, None,
                        os.path.dirname(bp_exe), C.byref(si), C.byref(pi))
assert ok, C.get_last_error()
hits = []
while len(hits) < 100:
    ev = df.DEBUG_EVENT()
    if not k32.WaitForDebugEvent(C.byref(ev), 20000):
        print("timeout"); break
    code = ev.dwDebugEventCode
    cont = df.DBG_CONTINUE
    if code == df.EXCEPTION_DEBUG_EVENT:
        er = ev.u.Exception.ExceptionRecord
        if er.ExceptionCode == 0x80000003:
            ht = k32.OpenThread(0x1F03FF, False, ev.dwThreadId)
            ctx = df.get_thread_context(ht)
            rip = ctx.Rip
            rva = (rip - ib) & 0xffffffff
            if rva in bps:
                buf = (C.c_ubyte * 1)(bps[rva])
                written = C.c_size_t()
                k32.WriteProcessMemory(pi.hProcess, C.c_void_p(rip), buf, 1, C.byref(written))
                hits.append((rva, ctx.Rax, ctx.Rcx, ctx.Rdx, ctx.R8, ctx.R9, ctx.Rsp, ctx.Rbp, ctx.Rsi))
            else:
                hits.append(("sys", rip))
            k32.CloseHandle(ht)
        elif er.ExceptionCode == 0xC0000005:
            ht = k32.OpenThread(0x1F03FF, False, ev.dwThreadId)
            ctx = df.get_thread_context(ht)
            print("AV rip", hex(ctx.Rip), "rva", hex((ctx.Rip - ib) & 0xffffffff))
            print("RAX", hex(ctx.Rax), "RCX", hex(ctx.Rcx), "RDX", hex(ctx.Rdx))
            print("R8", hex(ctx.R8), "R9", hex(ctx.R9), "RSI", hex(ctx.Rsi))
            print("RBP", hex(ctx.Rbp), "RSP", hex(ctx.Rsp))
            for off in range(0, 0x80, 8):
                v = df.read_u64(pi.hProcess, ctx.Rsp + off)
                print(f"  [rsp+{off:#x}] = {v:#x}")
            hits.append(("AV", ctx.Rip))
            k32.CloseHandle(ht)
            break
        else:
            if er.ExceptionCode not in (0x80000004,):
                cont = df.DBG_EXCEPTION_NOT_HANDLED
    elif code == df.EXIT_PROCESS_DEBUG_EVENT:
        print("exit", ev.u.ExitProcess.dwExitCode); break
    k32.ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, cont)

print("--- hits ---")
for h in hits:
    if h[0] in ("AV", "sys"):
        print(h[0], hex(h[1]))
    else:
        rva,rax,rcx,rdx,r8,r9,rsp,rbp,rsi = h
        print(f"hit {rva:#07x} rax={rax:#x} rcx={rcx:#x} rdx={rdx:#x} r8={r8:#x} r9={r9:#x} rsi={rsi:#x} rbp={rbp:#x}")
