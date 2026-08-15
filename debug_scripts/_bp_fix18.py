import ctypes as C, struct, sys, os
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
sys.path.insert(0,".")
import dbg_fault as df
md=Cs(CS_ARCH_X86, CS_MODE_64)
# verify patch
pe=open("build_univ230/cmd_fix18.exe","rb").read()
e=struct.unpack_from("<I",pe,0x3C)[0]
ns=struct.unpack_from("<H",pe,e+6)[0]; so=struct.unpack_from("<H",pe,e+20)[0]; sec=e+24+so
for i in range(ns):
    o=sec+i*40
    if pe[o:o+5]==b".text":
        vs,va,rs,rp=struct.unpack_from("<IIII",pe,o+8); break
print("==== cadd region ====")
for insn in md.disasm(pe[rp+(0xcadd-va):rp+(0xcb40-va)], 0x80000000+0xcadd):
    print(f"  {insn.address:#x}: {insn.mnemonic} {insn.op_str}")

k32=C.WinDLL("kernel32", use_last_error=True)
df.suppress_fault_ui()
os.chdir("build_univ230")
exe=os.path.abspath("cmd_fix18.exe")
IB=0x80000000
BPS={
 IB+0xcb10: "before_halloc",
 IB+0xcb2c: "after_halloc",
 IB+0xcb39: "cmp_halloc",
 IB+0xcbf8: "fail_path",
 IB+0xcb50: "p_cb50",
 IB+0xcba0: "p_cba0",
 IB+0xc627: "after_print",
}
si=df.STARTUPINFO(); si.cb=C.sizeof(si); pi=df.PROCESS_INFORMATION()
cmd=C.create_unicode_buffer(f'"{exe}" /c echo w2ktest')
assert k32.CreateProcessW(exe,cmd,None,None,False,df.DEBUG_ONLY_THIS_PROCESS,None,os.getcwd(),C.byref(si),C.byref(pi))
orig={}; de=df.DEBUG_EVENT(); skips=0
while k32.WaitForDebugEvent(C.byref(de),25000):
    cont=df.DBG_CONTINUE
    if de.dwDebugEventCode==df.CREATE_PROCESS_DEBUG_EVENT:
        for va in BPS:
            b=df.read_process_mem(pi.hProcess,va,1)
            if b: orig[va]=b[0]; df.patch_byte(pi.hProcess,va,0xCC)
        if de.u.CreateProcessInfo.hFile: k32.CloseHandle(de.u.CreateProcessInfo.hFile)
    elif de.dwDebugEventCode==df.EXCEPTION_DEBUG_EVENT:
        er=de.u.Exception.ExceptionRecord; code=er.ExceptionCode&0xffffffff; addr=er.ExceptionAddress
        if code==0x80000003:
            bp=addr if addr in orig else (addr-1 if addr-1 in orig else None)
            if bp is not None:
                ctx=df.get_thread_context(pi.hThread)
                df.patch_byte(pi.hProcess,bp,orig[bp]); ctx.Rip=bp; ctx.EFlags&=~0x100
                k32.SetThreadContext(pi.hThread,C.byref(ctx))
                print(f"HIT {BPS[bp]} rax={ctx.Rax:#x} rcx={ctx.Rcx:#x} rdx={ctx.Rdx:#x} r8={ctx.R8:#x}")
            else:
                skips+=1
                if skips>12:
                    print("int3",hex(df.get_thread_context(pi.hThread).Rip)); k32.TerminateProcess(pi.hProcess,1); break
        elif code==0xC0000005:
            ctx=df.get_thread_context(pi.hThread)
            print("AV",hex(ctx.Rip),hex(ctx.Rax),hex(ctx.Rcx),hex(ctx.Rdx),hex(ctx.R8))
            k32.TerminateProcess(pi.hProcess,1); break
        elif code==0xC0000374:
            print("HEAP",hex(df.get_thread_context(pi.hThread).Rip)); k32.TerminateProcess(pi.hProcess,1); break
        elif code!=0x80000004: cont=df.DBG_EXCEPTION_NOT_HANDLED
    elif de.dwDebugEventCode==df.EXIT_PROCESS_DEBUG_EVENT:
        print("exit",hex(de.u.ExitProcess.dwExitCode&0xffffffff)); break
    k32.ContinueDebugEvent(de.dwProcessId,de.dwThreadId,cont)
