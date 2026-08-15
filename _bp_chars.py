import ctypes as C, sys, time
from pathlib import Path
sys.path.insert(0, ".")
from dbg_fault import *

# Break at getchar AFTER our stub returns: ret at 0x448e6 (or eax,-1; ret)
# Also break at 0x448ef (have-char path after jne)
exe = str(Path("build_univ207/cmd_pure.exe").resolve())
cwd = str(Path("build_univ207").resolve())
si = STARTUPINFO(); si.cb = C.sizeof(si); pi = PROCESS_INFORMATION()
k32.CreateProcessW(exe, C.create_unicode_buffer('"%s" /c echo w2ktest' % exe),
                   None, None, False, DEBUG_ONLY_THIS_PROCESS, None, cwd,
                   C.byref(si), C.byref(pi))
base = None; de = DEBUG_EVENT(); t0 = time.time()
# break at cmp word [rcx],0xd which is right after our stub (have-char continues)
# RVA 0x448ef from disasm jne target
bp_sites = {}
chars = []
hits = 0
while time.time() - t0 < 6:
    if not k32.WaitForDebugEvent(C.byref(de), 500):
        continue
    st = DBG_CONTINUE
    if de.dwDebugEventCode == CREATE_PROCESS_DEBUG_EVENT:
        base = de.u.CreateProcessInfo.lpBaseOfImage
        # BP on: after stub jne target 0x448ef (cmp CR), and on WEOF ret 0x448e5 area
        for rva, name in [(0x448ef, "have"), (0x448e5, "weof")]:
            o = C.c_ubyte(); n = C.c_size_t()
            k32.ReadProcessMemory(pi.hProcess, C.c_void_p(base + rva), C.byref(o), 1, C.byref(n))
            bp_sites[rva] = o.value
            k32.WriteProcessMemory(pi.hProcess, C.c_void_p(base + rva), C.byref(C.c_ubyte(0xCC)), 1, C.byref(n))
        if de.u.CreateProcessInfo.hFile:
            k32.CloseHandle(de.u.CreateProcessInfo.hFile)
    elif de.dwDebugEventCode == EXCEPTION_DEBUG_EVENT:
        er = de.u.Exception.ExceptionRecord
        ecode = er.ExceptionCode & 0xffffffff
        addr = er.ExceptionAddress or 0
        ctx = CONTEXT(); ctx.ContextFlags = CONTEXT_FULL
        k32.GetThreadContext(pi.hThread, C.byref(ctx))
        if ecode == 0x80000003 and base:
            rva = addr - base
            if rva in bp_sites:
                hits += 1
                eax = ctx.Rax & 0xffffffff
                rcx = ctx.Rcx
                # for have-path, char about to be tested is [rcx]
                ch = -1
                if rva == 0x448ef:
                    w = C.c_uint16(); n = C.c_size_t()
                    k32.ReadProcessMemory(pi.hProcess, C.c_void_p(rcx), C.byref(w), 2, C.byref(n))
                    ch = w.value
                    chars.append(ch)
                else:
                    chars.append(("WEOF", eax))
                if hits <= 30:
                    fa = C.c_uint32(); n = C.c_size_t()
                    k32.ReadProcessMemory(pi.hProcess, C.c_void_p(base + 0x5bae0), C.byref(fa), 4, C.byref(n))
                    print("hit", hits, "rva", hex(rva), "ch", ch if rva==0x448ef else hex(eax), "fae0", hex(fa.value))
                # restore, step, rearm
                n = C.c_size_t()
                k32.WriteProcessMemory(pi.hProcess, C.c_void_p(addr), C.byref(C.c_ubyte(bp_sites[rva])), 1, C.byref(n))
                ctx.Rip = addr; ctx.EFlags |= 0x100
                k32.SetThreadContext(pi.hThread, C.byref(ctx))
                # single step handled below
                if hits >= 40:
                    break
                continue
        if ecode == 0x80000004:
            # rearm all
            n = C.c_size_t()
            for rva, orig in bp_sites.items():
                k32.WriteProcessMemory(pi.hProcess, C.c_void_p(base + rva), C.byref(C.c_ubyte(0xCC)), 1, C.byref(n))
            ctx.EFlags &= ~0x100
            k32.SetThreadContext(pi.hThread, C.byref(ctx))
        elif ecode in (0xC00000FD, 0xC0000005):
            print("fault", hex(ecode)); break
        elif ecode not in (0x80000003, 0x80000004):
            st = DBG_EXCEPTION_NOT_HANDLED if de.u.Exception.dwFirstChance else DBG_CONTINUE
    elif de.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT:
        print("exit"); break
    k32.ContinueDebugEvent(de.dwProcessId, de.dwThreadId, st)
k32.TerminateProcess(pi.hProcess, 1)
# summarize chars
cs = []
for c in chars:
    if isinstance(c, tuple):
        cs.append("WEOF")
    elif c == 0xd: cs.append("CR")
    elif c == 0xa: cs.append("LF")
    elif 32 <= c < 127: cs.append(chr(c))
    else: cs.append(hex(c))
print("chars:", "".join(cs) if all(isinstance(x,str) and len(x)==1 for x in cs) else cs)
print("hits", hits)