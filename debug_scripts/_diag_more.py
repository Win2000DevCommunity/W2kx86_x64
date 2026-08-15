import ctypes as C
import os
import struct
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

si = df.STARTUPINFO()
si.cb = C.sizeof(si)
pi = df.PROCESS_INFORMATION()
assert k32.CreateProcessW(
    None, C.create_unicode_buffer(cmdline), None, None, False,
    df.DEBUG_PROCESS | df.DEBUG_ONLY_THIS_PROCESS, None, workdir,
    C.byref(si), C.byref(pi),
)

def u16(b, o=0):
    return int.from_bytes(b[o:o+2], "little") if len(b) >= o+2 else 0

def u32(b, o=0):
    return int.from_bytes(b[o:o+4], "little") if len(b) >= o+4 else 0

def u64(b, o=0):
    return int.from_bytes(b[o:o+8], "little") if len(b) >= o+8 else 0

def read(proc, addr, n):
    return df.read_process_mem(proc, addr, n) or b""

def pe_exports(proc, base):
    hdr = read(proc, base, 0x40)
    if hdr[:2] != b"MZ":
        return {}
    e = u32(hdr, 0x3C)
    nt = read(proc, base + e, 0x120)
    exp_rva = u32(nt, 24 + 0x70)
    if not exp_rva:
        return {}
    ed = read(proc, base + exp_rva, 0x28)
    nnames = u32(ed, 24)
    names = u32(ed, 32)
    ords = u32(ed, 36)
    funcs = u32(ed, 28)
    out = {}
    for i in range(min(nnames, 4000)):
        nr = u32(read(proc, base + names + i * 4, 4), 0)
        name = read(proc, base + nr, 64).split(b"\x00")[0].decode("latin1", "replace")
        ord_i = u16(read(proc, base + ords + i * 2, 2), 0)
        fr = u32(read(proc, base + funcs + ord_i * 4, 4), 0)
        out[name] = base + fr
    return out

def peb_cmdline(proc, base):
    # x64 PEB via GS:[0x60]; ProcessParameters at PEB+0x20; CommandLine UNICODE_STRING at +0x70
    # Under debugger we can use NtQueryInformationProcess, but simpler: read TEB
    # Actually dbg_fault may have helpers — use Wow64? Native x64 process.
    # Read GS isn't available cross-process easily. Use PEB from process params via NtQuery.
    ntdll = C.WinDLL("ntdll")
    ProcessBasicInformation = 0
    class PBI(C.Structure):
        _fields_ = [("Reserved1", C.c_void_p), ("PebBaseAddress", C.c_void_p),
                    ("Reserved2", C.c_void_p * 2), ("UniqueProcessId", C.c_void_p),
                    ("Reserved3", C.c_void_p)]
    pbi = PBI()
    ntdll.NtQueryInformationProcess(proc, ProcessBasicInformation, C.byref(pbi), C.sizeof(pbi), None)
    peb = int(pbi.PebBaseAddress or 0)
    if not peb:
        return None, None
    params = u64(read(proc, peb + 0x20, 8))
    if not params:
        return peb, None
    # UNICODE_STRING CommandLine at ProcessParameters+0x70: USHORT Len, Max, PWSTR Buffer
    us = read(proc, params + 0x70, 16)
    length = u16(us, 0)
    buf = u64(us, 8)
    raw = read(proc, buf, min(length, 512))
    try:
        s = raw.decode("utf-16le", "replace")
    except Exception:
        s = repr(raw)
    return peb, s

base = 0
mods = {}
bps = {}  # addr -> orig byte
more_count = 0
de = df.DEBUG_EVENT()
t0 = time.time()

while time.time() - t0 < 10:
    if not k32.WaitForDebugEvent(C.byref(de), 500):
        continue
    st = df.DBG_CONTINUE
    code = de.dwDebugEventCode
    if code == df.CREATE_PROCESS_DEBUG_EVENT:
        base = int(de.u.CreateProcessInfo.lpBaseOfImage)
        print("base", hex(base))
    elif code == df.LOAD_DLL_DEBUG_EVENT:
        lb = int(de.u.LoadDll.lpBaseOfDll)
        # resolve name later via exports scan of kernel32
        mods[lb] = True
        # try resolve WriteFile when kernel32 loads — scan exports
        ex = pe_exports(pi.hProcess, lb)
        for nm in ("WriteFile", "WriteConsoleW", "WriteConsoleA"):
            if nm in ex and ex[nm] not in bps:
                addr = ex[nm]
                orig = read(pi.hProcess, addr, 1)
                if orig:
                    # poke INT3
                    written = C.c_size_t()
                    buf = (C.c_char * 1)(0xCC)
                    if k32.WriteProcessMemory(pi.hProcess, C.c_uint64(addr), buf, 1, C.byref(written)):
                        bps[addr] = orig[0]
                        print("bp", nm, hex(addr))
    elif code == df.EXCEPTION_DEBUG_EVENT:
        er = de.u.Exception.ExceptionRecord
        ecode = er.ExceptionCode & 0xFFFFFFFF
        addr = er.ExceptionAddress
        first = de.u.Exception.dwFirstChance
        if ecode == 0x80000003:
            ctx = df.get_thread_context(pi.hThread)
            rip = int(ctx.Rip)
            hit = rip if rip in bps else (rip-1 if (rip-1) in bps else None)
            if hit is None:
                k32.ContinueDebugEvent(de.dwProcessId, de.dwThreadId, st)
                continue
            rip = hit
            ctx.Rip = rip
            # restore and set TF to re-exec
            orig = bps[rip]
            written = C.c_size_t()
            buf = (C.c_char * 1)(orig)
            k32.WriteProcessMemory(pi.hProcess, C.c_uint64(rip), buf, 1, C.byref(written))
            # Read buffer: WriteFile(h, buf, n) → rcx, rdx, r8
            # WriteConsoleW(h, buf, nchars) → rcx, rdx, r8
            n = ctx.R8 & 0xFFFFFFFF
            ptr = ctx.Rdx
            raw = read(pi.hProcess, ptr, min(n * 2 + 4, 200))
            txt_u = raw[: n * 2].decode("utf-16le", "replace") if n < 200 else ""
            txt_a = raw[:n].decode("latin1", "replace") if n < 200 else ""
            interesting = ("More" in txt_u) or ("More" in txt_a) or ("w2ktest" in txt_u) or ("echo" in txt_u.lower())
            if interesting or more_count < 2:
                print("--- write ---")
                print("RIP", hex(rip), "n", n)
                print("utf16", ascii(txt_u[:80]))
                print("ascii", ascii(txt_a[:80]))
                peb, cl = peb_cmdline(pi.hProcess, base)
                print("cmdline", ascii(cl))
                # stack returns in main
                sp = ctx.Rsp
                stack = read(pi.hProcess, sp, 0x80)
                print("returns:", end=" ")
                for i in range(0, 0x80, 8):
                    v = u64(stack, i)
                    if base <= v < base + 0x100000:
                        print(hex(v - base), end=" ")
                print()
                # dump [rbp+0x10] and nearby if rbp looks like stack
                if 0x10000 <= ctx.Rbp < 0x200000:
                    fr = read(pi.hProcess, ctx.Rbp - 0x50, 0x80)
                    print("frame@rbp-0x50 qwords:", [hex(u64(fr, i)) for i in range(0, 0x80, 8)])
            if "More" in txt_u or "More" in txt_a:
                more_count += 1
                if more_count >= 2:
                    print("got More? x2 — stopping")
                    k32.TerminateProcess(pi.hProcess, 1)
                    break
            # dump flags at [rbp+0x18] if plausible
            if 0x10000 <= ctx.Rbp < 0x200000:
                fl = read(pi.hProcess, ctx.Rbp + 0x18, 4)
                print('flags[rbp+0x18]', hex(u32(fl)) if fl else None)
                # dump possible line buffers as utf16
                for off in (-0x8, 0x8, 0x10, 0x20, 0x28):
                    slot = read(pi.hProcess, ctx.Rbp + off, 8)
                    if not slot: continue
                    ptr = u64(slot)
                    if 0x10000 <= ptr < 0x800000000:
                        raw = read(pi.hProcess, ptr, 64)
                        try:
                            s = raw.decode('utf-16le','replace').split('\x00')[0][:40]
                        except Exception:
                            s = ''
                        if s and any(c.isprintable() or c in '"' for c in s[:8]):
                            print(f'  [rbp{off:+#x}]->', hex(ptr), ascii(s))
            # skip one insn: advance RIP past restored byte, re-arm bp
            # (we restored orig at rip; execute by setting RIP and re-arming later via TF alternative)
            # Simpler: write back INT3 after Continue by using hardware - just don't re-arm same hit
            # Re-arm all bps now that we restored this one for execution — but then we infinite loop.
            # Use: leave restored, set TF via context if available
            class CTX(C.Structure):
                pass
            # fallback: Terminate after first More? with dumps
            if more_count >= 1:
                print('stop after first More? with dumps')
                k32.TerminateProcess(pi.hProcess, 1)
                break
            # re-arm this bp after single-byte step using Resume + rewrite on next event
            # For now re-write INT3 immediately would loop; advance RIP by 0 and use Continue with restored byte,
            # then on next instruction boundary we miss. Accept one-shot.
            pass
        elif ecode == 0x80000004:
            for a, ob in list(bps.items()):
                written = C.c_size_t()
                buf = (C.c_char * 1)(0xCC)
                k32.WriteProcessMemory(pi.hProcess, C.c_uint64(a), buf, 1, C.byref(written))
        elif ecode == 0xC0000005:
            ctx = df.get_thread_context(pi.hThread)
            print("AV RIP", hex(ctx.Rip), "RAX", hex(ctx.Rax), "RCX", hex(ctx.Rcx), "RBP", hex(ctx.Rbp))
            peb, cl = peb_cmdline(pi.hProcess, base)
            print("cmdline", ascii(cl))
            break
    k32.ContinueDebugEvent(de.dwProcessId, de.dwThreadId, st)

k32.CloseHandle(pi.hProcess)
k32.CloseHandle(pi.hThread)
print("more_count", more_count)