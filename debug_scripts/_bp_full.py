import sys, ctypes as C, struct, os
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
watch = [0x3624d, 0x1e62c, 0x3988e, 0x39895, 0x1d4f4, 0x1d534, 0x1d574, 0x1d5b4,
         0x1d5dd, 0x1d603, 0x1d61a, 0x1e2b4, 0x1d7f4, 0x1ea3c, 0x1d35c, 0x34161]
for rva in watch:
    if 0 <= rva-va < len(out):
        bps[rva] = out[rva-va]
        out[rva-va] = 0xCC
pe[rp:rp+rs] = out
bp_exe = os.path.abspath(r"build_univ228\full_bp.exe")
open(bp_exe, "wb").write(pe)

k32 = df.k32
si = df.STARTUPINFO(); si.cb = C.sizeof(si)
pi = df.PROCESS_INFORMATION()
cmdline = C.create_unicode_buffer(f'"{bp_exe}" /c echo w2ktest')
ok = k32.CreateProcessW(None, cmdline, None, None, False,
                        df.DEBUG_ONLY_THIS_PROCESS, None,
                        os.path.dirname(bp_exe), C.byref(si), C.byref(pi))
assert ok, C.get_last_error()
hits = []
base = None
while len(hits) < 80:
    ev = df.DEBUG_EVENT()
    if not k32.WaitForDebugEvent(C.byref(ev), 15000):
        print("timeout"); break
    code = ev.dwDebugEventCode
    cont = df.DBG_CONTINUE
    if code == df.EXCEPTION_DEBUG_EVENT:
        er = ev.u.Exception.ExceptionRecord
        addr = er.ExceptionAddress
        if base is None:
            # try main module
            pass
        if er.ExceptionCode == 0x80000003:  # BREAKPOINT
            ctx = df.get_thread_context(ev.dwThreadId)
            rip = ctx.Rip
            rva = (rip - ib) & 0xffffffff
            # restore + step
            if rva in bps:
                # write original back in process
                buf = (C.c_ubyte * 1)(bps[rva])
                written = C.c_size_t()
                k32.WriteProcessMemory(pi.hProcess, C.c_uint64(rip), buf, 1, C.byref(written))
                hits.append((rva, ctx.Rax & 0xffffffffffffffff, ctx.Rcx & 0xffffffffffffffff,
                             ctx.Rdx & 0xffffffffffffffff, ctx.R8 & 0xffffffffffffffff,
                             ctx.R9 & 0xffffffffffffffff, ctx.Rsp & 0xffffffffffffffff,
                             ctx.Rbp & 0xffffffffffffffff))
                # set TF to re-arm? just continue without re-arm for one-shot
                ctx.EFlags |= 0x100  # TF - actually skip, one-shot is fine
                # need to set context with Rip unchanged (on CC, Rip points at CC)
                # After writing original, Rip still at insn - good
                df.k32.SetThreadContext(C.windll.kernel32.OpenThread(0x1F03FF, False, ev.dwThreadId), C.byref(ctx))
            else:
                hits.append(("other_bp", rip, 0,0,0,0,0,0))
        elif er.ExceptionCode == 0xC0000005:
            ctx = df.get_thread_context(ev.dwThreadId)
            print("AV rip", hex(ctx.Rip), "rva", hex((ctx.Rip-ib)&0xffffffff),
                  "acc", hex(er.ExceptionInformation[1] if er.NumberParameters>1 else 0))
            print("RAX", hex(ctx.Rax), "RCX", hex(ctx.Rcx), "RBP", hex(ctx.Rbp), "RSP", hex(ctx.Rsp))
            hits.append(("AV", ctx.Rip, ctx.Rax, ctx.Rcx, ctx.R8, ctx.R9, ctx.Rsp, ctx.Rbp))
            break
        else:
            cont = df.DBG_EXCEPTION_NOT_HANDLED
    elif code == df.EXIT_PROCESS_DEBUG_EVENT:
        print("exit", ev.u.ExitProcess.dwExitCode); break
    elif code == df.CREATE_PROCESS_DEBUG_EVENT:
        base = ev.u.CreateProcessInfo.lpBaseOfImage
    k32.ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, cont)

for h in hits:
    if h[0] == "AV":
        print("AV", [hex(x) if isinstance(x,int) else x for x in h])
    elif h[0] == "other_bp":
        print("other", hex(h[1]))
    else:
        rva,rax,rcx,rdx,r8,r9,rsp,rbp = h
        print(f"hit {rva:#x} rax={rax:#x} rcx={rcx:#x} rdx={rdx:#x} r8={r8:#x} r9={r9:#x} rsp={rsp:#x} rbp={rbp:#x}")
