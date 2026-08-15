import ctypes as C, struct, sys
from pathlib import Path
sys.path.insert(0, ".")
import dbg_fault as df
df.suppress_fault_ui()
k32 = df.k32
exe = str(Path("build_univ164/cmd_pure.exe").resolve())
si = df.STARTUPINFO(); si.cb = C.sizeof(si)
pi = df.PROCESS_INFORMATION()
cmd = '"' + exe + '" /c echo w2ktest'
assert k32.CreateProcessW(exe, cmd, None, None, False, df.DEBUG_ONLY_THIS_PROCESS, None, str(Path(exe).parent), C.byref(si), C.byref(pi))
CONTEXT_FULL = 0x10001F
class CTX(C.Structure):
    _fields_ = [("P1",C.c_uint64),("P2",C.c_uint64),("P3",C.c_uint64),("P4",C.c_uint64),("P5",C.c_uint64),("P6",C.c_uint64),("ContextFlags",C.c_uint32),("MxCsr",C.c_uint32),("SegCs",C.c_uint16),("SegDs",C.c_uint16),("SegEs",C.c_uint16),("SegFs",C.c_uint16),("SegGs",C.c_uint16),("SegSs",C.c_uint16),("EFlags",C.c_uint32),("Dr0",C.c_uint64),("Dr1",C.c_uint64),("Dr2",C.c_uint64),("Dr3",C.c_uint64),("Dr6",C.c_uint64),("Dr7",C.c_uint64),("Rax",C.c_uint64),("Rcx",C.c_uint64),("Rdx",C.c_uint64),("Rbx",C.c_uint64),("Rsp",C.c_uint64),("Rbp",C.c_uint64),("Rsi",C.c_uint64),("Rdi",C.c_uint64),("R8",C.c_uint64),("R9",C.c_uint64),("R10",C.c_uint64),("R11",C.c_uint64),("R12",C.c_uint64),("R13",C.c_uint64),("R14",C.c_uint64),("R15",C.c_uint64),("Rip",C.c_uint64)]
de = df.DEBUG_EVENT(); t0 = __import__("time").time()
while __import__("time").time()-t0 < 30:
    if not k32.WaitForDebugEvent(C.byref(de), 1000): continue
    if de.dwDebugEventCode == df.EXCEPTION_DEBUG_EVENT:
        er = de.u.Exception; ec = er.ExceptionRecord.ExceptionCode
        if ec == 0xC0000005 and er.dwFirstChance:
            ctx = CTX(); ctx.ContextFlags = CONTEXT_FULL
            k32.GetThreadContext(pi.hThread, C.byref(ctx))
            print("RIP", hex(ctx.Rip), "RSP", hex(ctx.Rsp), "RBP", hex(ctx.Rbp))
            print("RAX", hex(ctx.Rax), "RCX", hex(ctx.Rcx), "RDX", hex(ctx.Rdx), "R8", hex(ctx.R8))
            print("RSI", hex(ctx.Rsi), "RDI", hex(ctx.Rdi), "R13", hex(ctx.R13), "R14", hex(ctx.R14), "R15", hex(ctx.R15))
            # info from exception record
            er2 = er.ExceptionRecord
            print("numparams", er2.NumberParameters)
            for i in range(min(er2.NumberParameters, 4)):
                print(" param", i, hex(er2.ExceptionInformation[i]))
            raw = df.read_process_mem(pi.hProcess, ctx.Rsp, 0x200) or b""
            print("--- stack qwords ---")
            for off in range(0, min(len(raw), 0x180), 8):
                v = struct.unpack_from("<Q", raw, off)[0]
                tag = ""
                if 0x80001000 <= v < 0x80058000: tag = " TEXT"
                elif 0x80058000 <= v < 0x80066000: tag = " DATA"
                elif v == 0x80060320: tag = " BUF"
                elif 0x7FF000000000 <= v: tag = " MOD?"
                if v != 0 or off < 0x40:
                    print(f"  [{off:03x}] {v:016x}{tag}")
            # bytes just before RSP (if ret, previous slot)
            raw2 = df.read_process_mem(pi.hProcess, ctx.Rsp - 0x40, 0x40) or b""
            print("--- below RSP ---")
            for off in range(0, 0x40, 8):
                v = struct.unpack_from("<Q", raw2, off)[0]
                print(f"  [rsp-{0x40-off:02x}] {v:016x}")
            break
        k32.ContinueDebugEvent(de.dwProcessId, de.dwThreadId, df.DBG_EXCEPTION_NOT_HANDLED)
    elif de.dwDebugEventCode == df.EXIT_PROCESS_DEBUG_EVENT:
        break
    else:
        k32.ContinueDebugEvent(de.dwProcessId, de.dwThreadId, df.DBG_CONTINUE)
k32.TerminateProcess(pi.hProcess, 1)
