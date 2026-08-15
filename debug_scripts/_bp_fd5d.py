import sys, ctypes as C, struct, os
from ctypes import wintypes
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
sys.path.insert(0, ".")
import dbg_fault as df

# First show 36235
pe0 = bytearray(open(r"build_univ228\full.exe","rb").read())
e = struct.unpack_from("<I", pe0, 0x3C)[0]
ns = struct.unpack_from("<H", pe0, e+6)[0]
so = struct.unpack_from("<H", pe0, e+20)[0]
sec = e+24+so
ib = struct.unpack_from("<Q", pe0, e+24+24)[0]
for i in range(ns):
    o = sec+i*40
    if pe0[o:o+5] == b".text":
        vs,va,rs,rp = struct.unpack_from("<IIII", pe0, o+8); break
code = bytes(pe0[rp:rp+rs])
md = Cs(CS_ARCH_X86, CS_MODE_64)
print("==== 36235 ====")
for i, insn in enumerate(md.disasm(code[0x36235-va:0x36235-va+0x40], ib+0x36235)):
    print(f"  {insn.address:#x}: {insn.mnemonic} {insn.op_str}")
    if i>15: break

# Find FD5D epilogue - look for pop rdi; pop rsi; pop rbx; leave; ret near 1e64a region
print("==== scan epi near 1e700 ====")
for i, insn in enumerate(md.disasm(code[0x1e720-va:0x1e780-va], ib+0x1e720)):
    print(f"  {insn.address:#x}: {insn.mnemonic} {insn.op_str}")
    if i>30: break

exe = os.path.abspath(r"build_univ228\full.exe")
pe = bytearray(open(exe, "rb").read())
out = bytearray(pe[rp:rp+rs])
bps = {}
watch = [0x1e64a, 0x36235, 0x1e661, 0x1e67c, 0x1e6b1, 0x1e6fe, 0x1e742,
         0x1e725, 0x45894, 0x1e7a0, 0x1e7b0, 0x1e7c0]
# also find ret of fd5d by scanning
for off in range(0x1e640-va, min(0x1e7d0-va, len(out)-5)):
    # pop rdi; pop rsi; pop rbx; leave/mov rsp; ret patterns
    if out[off:off+4] == bytes([0x5f,0x5e,0x5b,0xc9]) or out[off:off+4] == bytes([0x5f,0x5e,0x5b,0x5d]):
        watch.append(va+off)
        print("epi candidate", hex(va+off), out[off:off+8].hex())

for rva in sorted(set(watch)):
    if 0 <= rva-va < len(out):
        bps[rva] = out[rva-va]
        out[rva-va] = 0xCC
pe[rp:rp+rs] = out
bp_exe = os.path.abspath(r"build_univ228\full_bp2.exe")
open(bp_exe, "wb").write(pe)

k32 = df.k32
k32.OpenThread.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
k32.OpenThread.restype = wintypes.HANDLE
si = df.STARTUPINFO(); si.cb = C.sizeof(si)
pi = df.PROCESS_INFORMATION()
cmdline = C.create_unicode_buffer(f'"{bp_exe}" /c echo w2ktest')
assert k32.CreateProcessW(None, cmdline, None, None, False, df.DEBUG_ONLY_THIS_PROCESS, None, os.path.dirname(bp_exe), C.byref(si), C.byref(pi))
hits=[]
while len(hits)<80:
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
                buf = (C.c_ubyte*1)(bps[rva])
                wr=C.c_size_t(); k32.WriteProcessMemory(pi.hProcess, C.c_void_p(rip), buf, 1, C.byref(wr))
                ctx.Rip = rip; k32.SetThreadContext(ht, C.byref(ctx))
                hits.append((rva, ctx.Rax, ctx.Rcx, ctx.Rbp, ctx.Rsp, ctx.Rsi, ctx.Rdi))
            k32.CloseHandle(ht)
        elif er.ExceptionCode == 0xC0000005:
            ht = k32.OpenThread(0x1F03FF, False, ev.dwThreadId)
            ctx = df.get_thread_context(ht)
            print("AV rip", hex(ctx.Rip), "rax", hex(ctx.Rax), "rbp", hex(ctx.Rbp), "rsp", hex(ctx.Rsp))
            for off in range(0, 0x50, 8):
                v = df.read_u64(pi.hProcess, ctx.Rsp + off)
                print(f"  [rsp+{off:#x}]={v:#x}")
            hits.append(("AV", ctx.Rip,0,0,0,0,0))
            k32.CloseHandle(ht); break
        elif er.ExceptionCode not in (0x80000004,):
            cont = df.DBG_EXCEPTION_NOT_HANDLED
    elif ev.dwDebugEventCode == df.EXIT_PROCESS_DEBUG_EVENT:
        print("exit", ev.u.ExitProcess.dwExitCode); break
    k32.ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, cont)
print("---")
for h in hits:
    if h[0]=="AV":
        print("AV", hex(h[1])); continue
    rva,rax,rcx,rbp,rsp,rsi,rdi=h
    print(f"hit {rva:#x} rax={rax:#x} rcx={rcx:#x} rdi={rdi:#x} rsi={rsi:#x} rbp={rbp:#x}")
