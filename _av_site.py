#!/usr/bin/env python3
import os
import dbg_fault as df
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
import pefile

EXE = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "win2000_x64", "cmd_shim.exe"))


def main():
    df.suppress_fault_ui()
    cmdline = f'"{EXE}" /c echo test'
    si = df.STARTUPINFO()
    si.cb = __import__("ctypes").sizeof(si)
    pi = df.PROCESS_INFORMATION()
    df.k32.CreateProcessW(
        EXE, __import__("ctypes").create_unicode_buffer(cmdline), None, None, False,
        df.DEBUG_ONLY_THIS_PROCESS, None, os.path.dirname(EXE), __import__("ctypes").byref(si), __import__("ctypes").byref(pi))
    base = None
    de = df.DEBUG_EVENT()
    n_av = 0
    while df.k32.WaitForDebugEvent(__import__("ctypes").byref(de), df.INFINITE):
        if de.dwDebugEventCode == df.CREATE_PROCESS_DEBUG_EVENT:
            base = de.u.CreateProcessInfo.lpBaseOfImage
        elif de.dwDebugEventCode == df.EXCEPTION_DEBUG_EVENT:
            er = de.u.Exception.ExceptionRecord
            ec = er.ExceptionCode & 0xFFFFFFFF
            ea = er.ExceptionAddress or 0
            rva = ea - (base or 0)
            fc = de.u.Exception.dwFirstChance
            if ec == 0xC0000005:
                n_av += 1
                ctx = df.get_thread_context(pi.hThread)
                in_main = base and base <= ea < base + 0x500000
                tag = f"main+0x{rva:x}" if in_main else f"0x{ea:x}"
                print(f"AV#{n_av} fc={fc} @ {tag} RIP={ctx.Rip:#x}")
                if in_main:
                    pe = pefile.PE(EXE, fast_load=True)
                    start = max(0, rva - 8)
                    for i in Cs(CS_ARCH_X86, CS_MODE_64).disasm(pe.get_data(start, 24), base + start):
                        print(f"  main+0x{i.address - base:x}: {i.mnemonic} {i.op_str}")
                if not fc or n_av >= 5:
                    break
        elif de.dwDebugEventCode == df.EXIT_PROCESS_DEBUG_EVENT:
            print(f"exit=0x{de.u.ExitProcess.dwExitCode & 0xFFFFFFFF:08x}")
            break
        df.k32.ContinueDebugEvent(de.dwProcessId, de.dwThreadId, df.DBG_CONTINUE)


if __name__ == "__main__":
    main()
