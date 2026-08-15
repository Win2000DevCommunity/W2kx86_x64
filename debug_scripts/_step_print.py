import struct, pathlib, ctypes as C, sys, os
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
sys.path.insert(0,".")
import dbg_fault as df
md=Cs(CS_ARCH_X86, CS_MODE_64)
pe=pathlib.Path("build_univ230/cmd_fix17.exe").read_bytes()
e=struct.unpack_from("<I",pe,0x3C)[0]
ns=struct.unpack_from("<H",pe,e+6)[0]; so=struct.unpack_from("<H",pe,e+20)[0]; sec=e+24+so
for i in range(ns):
    o=sec+i*40
    if pe[o:o+5]==b".text":
        vs,va,rs,rp=struct.unpack_from("<IIII",pe,o+8); break
print("==== c98a-ca40 ====")
for insn in md.disasm(pe[rp+(0xc98a-va):rp+(0xca80-va)], 0x80000000+0xc98a):
    print(f"  {insn.address:#x}: {insn.mnemonic} {insn.op_str}")

k32=C.WinDLL("kernel32", use_last_error=True)
df.suppress_fault_ui()
os.chdir("build_univ230")
exe=os.path.abspath("cmd_fix17.exe")
IB=0x80000000
BP=IB+0xc98a
si=df.STARTUPINFO(); si.cb=C.sizeof(si); pi=df.PROCESS_INFORMATION()
cmd=C.create_unicode_buffer(f'"{exe}" /c echo w2ktest')
assert k32.CreateProcessW(exe,cmd,None,None,False,df.DEBUG_ONLY_THIS_PROCESS,None,os.getcwd(),C.byref(si),C.byref(pi))
orig=None; de=df.DEBUG_EVENT(); tracing=False; steps=0
while k32.WaitForDebugEvent(C.byref(de),20000):
    cont=df.DBG_CONTINUE
    if de.dwDebugEventCode==df.CREATE_PROCESS_DEBUG_EVENT:
        orig=df.read_process_mem(pi.hProcess,BP,1)[0]
        df.patch_byte(pi.hProcess,BP,0xCC)
        if de.u.CreateProcessInfo.hFile: k32.CloseHandle(de.u.CreateProcessInfo.hFile)
    elif de.dwDebugEventCode==df.EXCEPTION_DEBUG_EVENT:
        er=de.u.Exception.ExceptionRecord; code=er.ExceptionCode&0xffffffff; addr=er.ExceptionAddress
        if code==0x80000003 and addr in (BP,BP+1):
            ctx=df.get_thread_context(pi.hThread)
            df.patch_byte(pi.hProcess,BP,orig); ctx.Rip=BP; ctx.EFlags|=0x100
            k32.SetThreadContext(pi.hThread,C.byref(ctx)); tracing=True
        elif code==0x80000004 and tracing:
            ctx=df.get_thread_context(pi.hThread)
            steps+=1
            b=df.read_process_mem(pi.hProcess,ctx.Rip,15) or b""
            ins=list(md.disasm(b, ctx.Rip))
            s=f"{ins[0].mnemonic} {ins[0].op_str}" if ins else "?"
            if steps<=40 or "call" in s:
                print(f"{steps:3d} {ctx.Rip:#x}: {s}  rax={ctx.Rax:#x} rcx={ctx.Rcx:#x}")
            if steps>80:
                k32.TerminateProcess(pi.hProcess,1); break
            ctx.EFlags|=0x100
            k32.SetThreadContext(pi.hThread,C.byref(ctx))
        elif code==0xC0000005:
            ctx=df.get_thread_context(pi.hThread)
            print("AV",hex(ctx.Rip),hex(ctx.Rax),hex(ctx.Rcx))
            k32.TerminateProcess(pi.hProcess,1); break
        elif code==0xC0000374:
            print("HEAP"); k32.TerminateProcess(pi.hProcess,1); break
        elif code not in (0x80000003,0x80000004):
            cont=df.DBG_EXCEPTION_NOT_HANDLED
    elif de.dwDebugEventCode==df.EXIT_PROCESS_DEBUG_EVENT:
        break
    k32.ContinueDebugEvent(de.dwProcessId,de.dwThreadId,cont)
