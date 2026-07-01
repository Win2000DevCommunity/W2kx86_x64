#!/usr/bin/env python3
import os
import ctypes as C
import dbg_fault as df

EXE = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "win2000_x64", "cmd_shim.exe"))
ENTRY = 0x8777


def patch_byte(proc, addr, val):
    old = C.c_uint32(0)
    k32 = df.k32
    k32.VirtualProtectEx(proc, C.c_void_p(addr & ~0xFFF), 0x1000, 0x40, C.byref(old))
    n = C.c_size_t(0)
    ok = k32.WriteProcessMemory(proc, C.c_void_p(addr), C.c_char(val), 1, C.byref(n))
    k32.VirtualProtectEx(proc, C.c_void_p(addr & ~0xFFF), 0x1000, old.value, C.byref(old))
    return ok and n.value == 1


def main():
    df.suppress_fault_ui()
    cmdline = f'"{EXE}" /c echo test'
    si = df.STARTUPINFO(); si.cb = C.sizeof(si)
    pi = df.PROCESS_INFORMATION()
    df.k32.CreateProcessW(EXE, C.create_unicode_buffer(cmdline), None, None, False,
                          df.DEBUG_ONLY_THIS_PROCESS, None, os.path.dirname(EXE), C.byref(si), C.byref(pi))
    base = None
    de = df.DEBUG_EVENT()
    entry_hit = False
    while df.k32.WaitForDebugEvent(C.byref(de), df.INFINITE):
        if de.dwDebugEventCode == df.CREATE_PROCESS_DEBUG_EVENT:
            base = de.u.CreateProcessInfo.lpBaseOfImage
            print(f"base=0x{base:x} start=0x{de.u.CreateProcessInfo.lpStartAddress:x}")
        elif de.dwDebugEventCode == df.EXCEPTION_DEBUG_EVENT:
            er = de.u.Exception.ExceptionRecord
            ec = er.ExceptionCode & 0xFFFFFFFF
            ea = er.ExceptionAddress or 0
            rva = ea - (base or 0) if base else 0
            if ec == 0x80000003 and not entry_hit and base and rva > 0x100000:
                ok = patch_byte(pi.hProcess, base + ENTRY, b"\xcc")
                print(f"patch entry+0x{ENTRY:x} ok={ok}")
            elif ec == 0x80000003 and rva == ENTRY:
                entry_hit = True
                ctx = df.get_thread_context(pi.hThread)
                print(f"ENTRY HIT RCX={ctx.Rcx:#x} RDX={ctx.Rdx:#x}")
                patch_byte(pi.hProcess, base + ENTRY, b"\x90")  # nop, continue
                ctx.Rip = base + ENTRY + 1
                df.k32.SetThreadContext(pi.hThread, C.byref(ctx))
            elif ec == 0x80000003:
                print(f"other bp rva=0x{rva:x}")
        elif de.dwDebugEventCode == df.EXIT_PROCESS_DEBUG_EVENT:
            print(f"exit=0x{de.u.ExitProcess.dwExitCode & 0xFFFFFFFF:08x} entry_hit={entry_hit}")
            break
        df.k32.ContinueDebugEvent(de.dwProcessId, de.dwThreadId, df.DBG_CONTINUE)


if __name__ == "__main__":
    main()
