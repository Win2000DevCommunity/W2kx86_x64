import ctypes as C
from ctypes import wintypes
import os, sys, time
import dbg_fault as df
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
exe = os.path.abspath(os.path.join("build_univ29", "cmd_pure.exe"))
cmdline = '"%s" /c echo w2ktest' % exe
k32 = df.k32
open(os.path.join("build_univ29", "empty_in.txt"), "wb").close()
GENERIC_READ=0x80000000; GENERIC_WRITE=0x40000000; OPEN_EXISTING=3; CREATE_ALWAYS=2; FILE_SHARE_READ=1
CreateFileW=k32.CreateFileW; CreateFileW.restype=wintypes.HANDLE
hIn=CreateFileW(r"build_univ29\empty_in.txt", GENERIC_READ, FILE_SHARE_READ, None, OPEN_EXISTING, 0, None)
hOut=CreateFileW(r"build_univ29\out2.txt", GENERIC_WRITE, FILE_SHARE_READ, None, CREATE_ALWAYS, 0, None)
hErr=CreateFileW(r"build_univ29\err2.txt", GENERIC_WRITE, FILE_SHARE_READ, None, CREATE_ALWAYS, 0, None)
class STARTUPINFO(C.Structure):
    _fields_=[("cb",wintypes.DWORD),("lpReserved",wintypes.LPWSTR),("lpDesktop",wintypes.LPWSTR),
              ("lpTitle",wintypes.LPWSTR),("dwX",wintypes.DWORD),("dwY",wintypes.DWORD),
              ("dwXSize",wintypes.DWORD),("dwYSize",wintypes.DWORD),("dwXCountChars",wintypes.DWORD),
              ("dwYCountChars",wintypes.DWORD),("dwFillAttribute",wintypes.DWORD),("dwFlags",wintypes.DWORD),
              ("wShowWindow",wintypes.WORD),("cbReserved2",wintypes.WORD),("lpReserved2",C.POINTER(C.c_byte)),
              ("hStdInput",wintypes.HANDLE),("hStdOutput",wintypes.HANDLE),("hStdError",wintypes.HANDLE)]
si=STARTUPINFO(); si.cb=C.sizeof(si); si.dwFlags=0x100
si.hStdInput=hIn; si.hStdOutput=hOut; si.hStdError=hErr
pi=df.PROCESS_INFORMATION()
ok=k32.CreateProcessW(exe, C.create_unicode_buffer(cmdline), None, None, True, 1|0x08000000, None, os.path.dirname(exe), C.byref(si), C.byref(pi))
print("created", bool(ok));
if not ok: raise SystemExit(1)
md=Cs(CS_ARCH_X86, CS_MODE_64); base=None; t0=time.time()
while time.time()-t0 < 25:
    de=df.DEBUG_EVENT()
    if not k32.WaitForDebugEvent(C.byref(de), 500):
        continue
    code=de.dwDebugEventCode
    if code==df.CREATE_PROCESS_DEBUG_EVENT:
        b=de.u.CreateProcessInfo.lpBaseOfImage
        if base is None:
            base=b; print("[base]", hex(base))
        k32.ContinueDebugEvent(de.dwProcessId, de.dwThreadId, df.DBG_CONTINUE); continue
    if code==df.EXCEPTION_DEBUG_EVENT:
        exc=de.u.Exception.ExceptionRecord; ec=exc.ExceptionCode
        if ec in (0x80000003, 0x4000001F) and de.u.Exception.dwFirstChance:
            k32.ContinueDebugEvent(de.dwProcessId, de.dwThreadId, df.DBG_CONTINUE); continue
        if ec==0xC0000005:
            rip=exc.ExceptionAddress
            print("FAULT", hex(ec), "RIP", hex(rip), ("main+"+hex(rip-base)) if base and base<=rip<base+0x100000 else "")
            ctx=df.CONTEXT(); ctx.ContextFlags=0x10001F
            ht=k32.OpenThread(0x1F03FF, False, de.dwThreadId); k32.GetThreadContext(ht, C.byref(ctx))
            print("RAX=%x RCX=%x RDX=%x RSI=%x RDI=%x R8=%x R9=%x RBP=%x RSP=%x" % (ctx.Rax,ctx.Rcx,ctx.Rdx,ctx.Rsi,ctx.Rdi,ctx.R8,ctx.R9,ctx.Rbp,ctx.Rsp))
            print("access", int(exc.ExceptionInformation[0]), "addr", hex(int(exc.ExceptionInformation[1])))
            raw=df.read_process_mem(pi.hProcess, rip, 16)
            for insn in md.disasm(raw, rip):
                print("insn", insn.mnemonic, insn.op_str); break
            for i in range(0, 0x80, 8):
                b=df.read_process_mem(pi.hProcess, ctx.Rsp+i, 8)
                if len(b)==8:
                    v=int.from_bytes(b, "little")
                    if base and base<=v<base+0x100000:
                        print("  [rsp+%x] main+%x" % (i, v-base))
            break
        k32.ContinueDebugEvent(de.dwProcessId, de.dwThreadId, df.DBG_EXCEPTION_NOT_HANDLED); continue
    if code==df.EXIT_PROCESS_DEBUG_EVENT:
        print("exit", de.u.ExitProcess.dwExitCode); break
    k32.ContinueDebugEvent(de.dwProcessId, de.dwThreadId, df.DBG_CONTINUE)
else:
    print("timeout")
k32.TerminateProcess(pi.hProcess, 1)

