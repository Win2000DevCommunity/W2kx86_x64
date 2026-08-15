import ctypes as C, struct, sys, os
sys.path.insert(0, ".")
import dbg_fault as df
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
k32=C.WinDLL("kernel32", use_last_error=True)
df.suppress_fault_ui()
os.chdir("build_univ230")
exe=os.path.abspath("cmd_fix5.exe")
IB=0x80000000
# show c5c0 path
pe=open(exe,"rb").read()
e=struct.unpack_from("<I",pe,0x3C)[0]
ns=struct.unpack_from("<H",pe,e+6)[0]; so=struct.unpack_from("<H",pe,e+20)[0]; sec=e+24+so
for i in range(ns):
    o=sec+i*40
    if pe[o:o+5]==b".text":
        vs,va,rs,rp=struct.unpack_from("<IIII",pe,o+8); break
md=Cs(CS_ARCH_X86,CS_MODE_64)
print("==== c5c0-c630 ====")
for insn in md.disasm(pe[rp+(0xc5c0-va):rp+(0xc630-va)], IB+0xc5c0):
    print(f"  {insn.address:#x}: {insn.mnemonic} {insn.op_str}")

NAMES={
 IB+0xc5c0:"alloc2",
 IB+0xc5c5:"after_alloc2",
 IB+0xc5e5:"call_28a04",
 IB+0xc5ea:"after_28a04",
 IB+0xc627:"call_big",
}
si=df.STARTUPINFO(); si.cb=C.sizeof(si); pi=df.PROCESS_INFORMATION()
cmd=C.create_unicode_buffer(f'"{exe}" /c echo w2ktest')
assert k32.CreateProcessW(exe,cmd,None,None,False,df.DEBUG_ONLY_THIS_PROCESS,None,os.getcwd(),C.byref(si),C.byref(pi))
orig={}; de=df.DEBUG_EVENT(); skips=0
while k32.WaitForDebugEvent(C.byref(de),25000):
    cont=df.DBG_CONTINUE
    if de.dwDebugEventCode==df.CREATE_PROCESS_DEBUG_EVENT:
        for va in NAMES:
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
                print("HIT",NAMES[bp],"rax",hex(ctx.Rax),"rcx",hex(ctx.Rcx),"rdx",hex(ctx.Rdx),"r8",hex(ctx.R8))
            else:
                skips+=1
                if skips>4:
                    ctx=df.get_thread_context(pi.hThread)
                    print("heap/int3",hex(ctx.Rip),hex(ctx.Rcx))
                    k32.TerminateProcess(pi.hProcess,1); break
        elif code==0xC0000005:
            ctx=df.get_thread_context(pi.hThread)
            print("AV",hex(ctx.Rip),hex(ctx.Rcx),hex(ctx.Rdx),hex(ctx.Rax))
            if de.u.Exception.dwFirstChance: cont=df.DBG_EXCEPTION_NOT_HANDLED
            else: k32.TerminateProcess(pi.hProcess,1); break
        elif code==0xC0000374:
            print("HEAP"); k32.TerminateProcess(pi.hProcess,1); break
        elif code!=0x80000004: cont=df.DBG_EXCEPTION_NOT_HANDLED
    elif de.dwDebugEventCode==df.EXIT_PROCESS_DEBUG_EVENT:
        print("exit",hex(de.u.ExitProcess.dwExitCode&0xffffffff)); break
    k32.ContinueDebugEvent(de.dwProcessId,de.dwThreadId,cont)
