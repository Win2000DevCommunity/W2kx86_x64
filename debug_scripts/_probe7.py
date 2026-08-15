import ctypes as C, os, time
from ctypes import wintypes
from dbg_fault import *

exe = os.path.abspath("build_univ171_both2/cmd_pure.exe")
cmdline = '"%s" /c echo w2ktest' % exe
si = STARTUPINFO(); si.cb = C.sizeof(si); pi = PROCESS_INFORMATION()
assert k32.CreateProcessW(exe, C.create_unicode_buffer(cmdline), None, None, False, DEBUG_ONLY_THIS_PROCESS, None, os.path.dirname(exe), C.byref(si), C.byref(pi))
base = None
de = DEBUG_EVENT(); first = 0; t0 = time.time()
samples = []
while time.time() - t0 < 8:
    if not k32.WaitForDebugEvent(C.byref(de), 100):
        ctx = CONTEXT(); ctx.ContextFlags = CONTEXT_FULL
        if k32.GetThreadContext(pi.hThread, C.byref(ctx)) and base:
            if base <= ctx.Rip < base + 0x200000:
                samples.append((ctx.Rip - base, ctx.Rsp))
        continue
    code = de.dwDebugEventCode; status = DBG_CONTINUE
    if code == CREATE_PROCESS_DEBUG_EVENT:
        base = de.u.CreateProcessInfo.lpBaseOfImage
        if de.u.CreateProcessInfo.hFile: k32.CloseHandle(de.u.CreateProcessInfo.hFile)
    elif code == LOAD_DLL_DEBUG_EVENT:
        if de.u.LoadDll.hFile: k32.CloseHandle(de.u.LoadDll.hFile)
    elif code == EXIT_PROCESS_DEBUG_EVENT:
        print("exit", hex(de.u.ExitProcess.dwExitCode & 0xffffffff)); break
    elif code == EXCEPTION_DEBUG_EVENT:
        er = de.u.Exception.ExceptionRecord
        ecode = er.ExceptionCode & 0xffffffff
        if ecode == 0x80000003 and first == 0:
            first = 1
        elif ecode == 0xC0000005:
            print("AV"); break
        elif ecode not in (0x80000003, 0x80000004):
            status = DBG_EXCEPTION_NOT_HANDLED
    k32.ContinueDebugEvent(de.dwProcessId, de.dwThreadId, status)
# print rsp trend when at 13890
pts = [(r,s) for r,s in samples if r == 0x13890]
print("samples", len(samples), "at_13890", len(pts))
if pts:
    print("rsp first/last", hex(pts[0][1]), hex(pts[-1][1]), "delta", pts[-1][1]-pts[0][1])
    print("unique rsp", len(set(s for _,s in pts)))
# overall rsp min max
if samples:
    rsps = [s for _,s in samples]
    print("rsp min/max", hex(min(rsps)), hex(max(rsps)), "range", max(rsps)-min(rsps))
k32.TerminateProcess(pi.hProcess, 1)
