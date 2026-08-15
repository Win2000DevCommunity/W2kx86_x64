"""Break at echo size helpers; dump node fields and alloc sizes."""
import ctypes as C, struct, sys, os
from ctypes import wintypes
sys.path.insert(0, ".")
import dbg_fault as df

k32 = C.WinDLL("kernel32", use_last_error=True)
df.suppress_fault_ui()

exe = os.path.abspath("build_univ229/cmd_diam.exe")
os.chdir("build_univ229")
exe = os.path.abspath("cmd_diam.exe")

IB = 0x80000000
BPS = {
    IB+0x28858: "lensum_entry",
    IB+0x288d7: "lensum_after_lens",  # add eax,edi
    IB+0x288ee: "lensum_alloc_call",
    IB+0xc514: "c514_entry",
    IB+0xc546: "c514_alloc20a",
    IB+0x189c4: "echo_entry",
    IB+0x19dc4: "heap_alloc",
}

si = df.STARTUPINFO(); si.cb = C.sizeof(si)
pi = df.PROCESS_INFORMATION()
cmd = C.create_unicode_buffer(f'"{exe}" /c echo w2ktest')
ok = k32.CreateProcessW(exe, cmd, None, None, False,
    df.DEBUG_ONLY_THIS_PROCESS, None, os.path.dirname(exe), C.byref(si), C.byref(pi))
if not ok:
    raise SystemExit("CreateProcess fail")

orig = {}
armed = False
hits = []
alloc_sizes = []
de = df.DEBUG_EVENT()

def read_u64(proc, a):
    b = df.read_process_mem(proc, a, 8)
    return struct.unpack("<Q", b)[0] if b and len(b)==8 else None

def read_u32(proc, a):
    b = df.read_process_mem(proc, a, 4)
    return struct.unpack("<I", b)[0] if b and len(b)==4 else None

def read_wstr(proc, a, n=64):
    b = df.read_process_mem(proc, a, n*2)
    if not b: return None
    try:
        return b.decode("utf-16-le", errors="replace").split("\0")[0][:60]
    except: return repr(b[:40])

while k32.WaitForDebugEvent(C.byref(de), 15000):
    cont = df.DBG_CONTINUE
    if de.dwDebugEventCode == df.CREATE_PROCESS_DEBUG_EVENT:
        base = de.u.CreateProcessInfo.lpBaseOfImage
        # image may relocate; use actual base
        # Our PE prefers 0x80000000; check
        print("base", hex(base))
        # re-arm BPs relative if needed
        delta = base - IB
        if delta:
            print("reloc delta", hex(delta))
        hproc = pi.hProcess
        for va, name in list(BPS.items()):
            a = va + delta
            b = df.read_process_mem(hproc, a, 1)
            if not b:
                print("no read", name, hex(a)); continue
            orig[a] = b[0]
            df.patch_byte(hproc, a, 0xCC)
            BPS[a] = name  # also key by actual
        armed = True
        if de.u.CreateProcessInfo.hFile:
            k32.CloseHandle(de.u.CreateProcessInfo.hFile)
    elif de.dwDebugEventCode == df.EXCEPTION_DEBUG_EVENT:
        er = de.u.Exception.ExceptionRecord
        code = er.ExceptionCode
        addr = er.ExceptionAddress
        if code == 0x80000003:  # BREAKPOINT
            # find BP: RIP is after CC on x64? Actually for software BP, address is the CC itself
            a = addr
            # try addr and addr (int3 at instruction)
            name = BPS.get(a) or BPS.get(a-1)
            bp_addr = a if a in orig else (a-1 if (a-1) in orig else None)
            if bp_addr is not None:
                ctx = df.get_thread_context(pi.hThread)
                # restore and rewind
                df.patch_byte(pi.hProcess, bp_addr, orig[bp_addr])
                ctx.Rip = bp_addr
                ctx.EFlags |= 0x100  # single step to re-arm? skip rearm for one-shot mostly
                k32.SetThreadContext(pi.hThread, C.byref(ctx))
                nm = BPS.get(bp_addr, "?")
                info = {"name": nm, "rip": hex(bp_addr), "rcx": hex(ctx.Rcx), "rdx": hex(ctx.Rdx),
                        "rax": hex(ctx.Rax), "rsi": hex(ctx.Rsi), "rdi": hex(ctx.Rdi),
                        "rbx": hex(ctx.Rbx), "rbp": hex(ctx.Rbp)}
                if "lensum" in nm or nm=="echo_entry" or nm=="c514_entry":
                    node = ctx.Rcx if nm!="lensum_after_lens" else ctx.Rsi
                    if nm.startswith("lensum"):
                        node = ctx.Rsi if ctx.Rsi else ctx.Rcx
                        # at entry rcx=node; after pushes rsi=node
                        if nm=="lensum_entry":
                            node = ctx.Rcx
                    if nm=="echo_entry" or nm=="c514_entry":
                        node = ctx.Rcx
                    p38 = read_u32(pi.hProcess, node+0x38) if node else None
                    p3c = read_u32(pi.hProcess, node+0x3c) if node else None
                    q38 = read_u64(pi.hProcess, node+0x38) if node else None
                    q3c = read_u64(pi.hProcess, node+0x3c) if node else None
                    info["node"] = hex(node) if node else None
                    info["d38"] = hex(p38) if p38 is not None else None
                    info["d3c"] = hex(p3c) if p3c is not None else None
                    info["q38"] = hex(q38) if q38 is not None else None
                    info["q3c"] = hex(q3c) if q3c is not None else None
                    if p38 and p38 > 0x10000:
                        info["s38"] = read_wstr(pi.hProcess, p38)
                    if p3c and p3c > 0x10000:
                        info["s3c"] = read_wstr(pi.hProcess, p3c)
                if nm=="lensum_after_lens":
                    info["len1_edi"] = hex(ctx.Rdi & 0xffffffff)
                    info["len2_eax"] = hex(ctx.Rax & 0xffffffff)
                    info["sum"] = hex((ctx.Rax+ctx.Rdi) & 0xffffffff)
                if nm in ("lensum_alloc_call","c514_alloc20a","heap_alloc"):
                    info["size"] = hex(ctx.Rcx)
                    alloc_sizes.append((nm, ctx.Rcx))
                hits.append(info)
                print(info)
                # re-arm except we consumed one-shot; re-patch for heap_alloc to see many
                if nm == "heap_alloc":
                    # single step then rearm
                    pass
                # limit
                if len(hits) > 40:
                    k32.TerminateProcess(pi.hProcess, 1)
                    break
            elif de.u.Exception.dwFirstChance and addr and int(addr) < 0x10000:
                # initial ntdll BP
                pass
            else:
                # unexpected BP
                if len(hits) < 3:
                    print("other bp", hex(addr))
        elif code in (0xC0000005, 0xC0000374):
            ctx = df.get_thread_context(pi.hThread)
            print("FAULT", hex(code), "rip", hex(ctx.Rip), "rcx", hex(ctx.Rcx), "rbp", hex(ctx.Rbp))
            print("alloc_sizes", alloc_sizes[-10:])
            print("last hits", hits[-5:])
            k32.TerminateProcess(pi.hProcess, code)
            break
        else:
            cont = df.DBG_EXCEPTION_NOT_HANDLED
    elif de.dwDebugEventCode == df.EXIT_PROCESS_DEBUG_EVENT:
        print("exit", hex(de.u.ExitProcess.dwExitCode))
        break
    k32.ContinueDebugEvent(de.dwProcessId, de.dwThreadId, cont)

print("TOTAL hits", len(hits))
for h in hits:
    print(h)
