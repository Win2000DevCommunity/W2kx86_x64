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
# sticky breakpoints: re-arm
watch = [0x36284, 0x36289, 0x3628a, 0x1e748, 0x1d530, 0x1d570, 0x1d5b0,
         0x45867, 0x34161]
for rva in watch:
    if 0 <= rva-va < len(out):
        bps[rva] = out[rva-va]
        out[rva-va] = 0xCC
pe[rp:rp+rs] = out
bp_exe = os.path.abspath(r"build_univ228\full_bp3.exe")
open(bp_exe, "wb").write(pe)

k32 = df.k32
k32.OpenThread.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
k32.OpenThread.restype = wintypes.HANDLE
si = df.STARTUPINFO(); si.cb = C.sizeof(si)
pi = df.PROCESS_INFORMATION()
cmdline = C.create_unicode_buffer(f'"{bp_exe}" /c echo w2ktest')
assert k32.CreateProcessW(None, cmdline, None, None, False, df.DEBUG_ONLY_THIS_PROCESS, None, os.path.dirname(bp_exe), C.byref(si), C.byref(pi))
hits=[]; counts={}
while sum(counts.values()) < 60:
    ev = df.DEBUG_EVENT()
    if not k32.WaitForDebugEvent(C.byref(ev), 20000):
        print("timeout"); break
    cont = df.DBG_CONTINUE
    if ev.dwDebugEventCode == df.EXCEPTION_DEBUG_EVENT:
        er = ev.u.Exception.ExceptionRecord
        if er.ExceptionCode == 0x80000003:
            ht = k32.OpenThread(0x1F03FF, False, ev.dwThreadId)
            ctx = df.get_thread_context(ht)
            rip = ctx.Rip - 1
            rva = (rip - ib) & 0xffffffff
            if rva in bps:
                # restore, record, single-step, re-arm
                buf = (C.c_ubyte*1)(bps[rva])
                wr=C.c_size_t(); k32.WriteProcessMemory(pi.hProcess, C.c_void_p(rip), buf, 1, C.byref(wr))
                ctx.Rip = rip
                retaddr = df.read_u64(pi.hProcess, ctx.Rsp) if rva in (0x3628a, 0x1e748, 0x1d530, 0x1d570, 0x1d5b0) else 0
                rbp8 = df.read_u64(pi.hProcess, ctx.Rbp+8) if ctx.Rbp else 0
                hits.append((rva, ctx.Rax, ctx.Rsp, ctx.Rbp, retaddr, rbp8))
                counts[rva] = counts.get(rva,0)+1
                # single step then re-arm
                ctx.EFlags |= 0x100
                k32.SetThreadContext(ht, C.byref(ctx))
                # mark pending rearm
                pending = rva
            else:
                pending = None
            k32.CloseHandle(ht)
        elif er.ExceptionCode == 0x80000004:  # single step
            ht = k32.OpenThread(0x1F03FF, False, ev.dwThreadId)
            ctx = df.get_thread_context(ht)
            # re-arm all
            for rva, orig in bps.items():
                addr = ib + rva
                buf = (C.c_ubyte*1)(0xCC)
                wr=C.c_size_t(); k32.WriteProcessMemory(pi.hProcess, C.c_void_p(addr), buf, 1, C.byref(wr))
            ctx.EFlags &= ~0x100
            k32.SetThreadContext(ht, C.byref(ctx))
            k32.CloseHandle(ht)
        elif er.ExceptionCode == 0xC0000005:
            ht = k32.OpenThread(0x1F03FF, False, ev.dwThreadId)
            ctx = df.get_thread_context(ht)
            print("AV rip", hex(ctx.Rip), "rax", hex(ctx.Rax), "rbp", hex(ctx.Rbp), "rsp", hex(ctx.Rsp))
            for off in range(0, 0x48, 8):
                print(f"  [rsp+{off:#x}]={df.read_u64(pi.hProcess, ctx.Rsp+off):#x}")
            k32.CloseHandle(ht); break
        else:
            cont = df.DBG_EXCEPTION_NOT_HANDLED
    elif ev.dwDebugEventCode == df.EXIT_PROCESS_DEBUG_EVENT:
        print("exit", ev.u.ExitProcess.dwExitCode); break
    k32.ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, cont)
print("counts", {hex(k):v for k,v in counts.items()})
for h in hits:
    rva,rax,rsp,rbp,retaddr,rbp8=h
    print(f"hit {rva:#x} rax={rax:#x} rsp={rsp:#x} rbp={rbp:#x} [rsp]={retaddr:#x} [rbp+8]={rbp8:#x}")
