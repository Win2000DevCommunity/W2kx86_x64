import ctypes as C, struct, sys, os
sys.path.insert(0, ".")
import dbg_fault as df
k32 = C.WinDLL("kernel32", use_last_error=True)
df.suppress_fault_ui()
os.chdir("build_univ229")
exe = os.path.abspath("cmd_diam.exe")
IB=0x80000000
BP_VA = IB+0x31ff0
si=df.STARTUPINFO(); si.cb=C.sizeof(si); pi=df.PROCESS_INFORMATION()
cmd=C.create_unicode_buffer(f'"{exe}" /c echo w2ktest')
assert k32.CreateProcessW(exe,cmd,None,None,False,df.DEBUG_ONLY_THIS_PROCESS,None,os.getcwd(),C.byref(si),C.byref(pi))
orig=None; hits=[]; de=df.DEBUG_EVENT(); pending=None

while k32.WaitForDebugEvent(C.byref(de),20000):
    cont=df.DBG_CONTINUE
    if de.dwDebugEventCode==df.CREATE_PROCESS_DEBUG_EVENT:
        orig=df.read_process_mem(pi.hProcess,BP_VA,1)[0]
        df.patch_byte(pi.hProcess,BP_VA,0xCC)
        if de.u.CreateProcessInfo.hFile: k32.CloseHandle(de.u.CreateProcessInfo.hFile)
    elif de.dwDebugEventCode==df.EXCEPTION_DEBUG_EVENT:
        er=de.u.Exception.ExceptionRecord; code=er.ExceptionCode&0xffffffff; addr=er.ExceptionAddress
        if code==0x80000003:
            bp = BP_VA if addr in (BP_VA, BP_VA+1) else None
            if addr==BP_VA or addr==BP_VA+1:
                ctx=df.get_thread_context(pi.hThread)
                df.patch_byte(pi.hProcess,BP_VA,orig)
                ctx.Rip=BP_VA
                ctx.EFlags |= 0x100  # TF rearm
                k32.SetThreadContext(pi.hThread,C.byref(ctx))
                pending=BP_VA
                ret=struct.unpack("<Q", df.read_process_mem(pi.hProcess,ctx.Rsp,8))[0]
                bad = ctx.Rcx > 0x100000000 or (ctx.Rcx and ctx.Rcx < 0x10000)
                rec=dict(n=len(hits),rcx=hex(ctx.Rcx),rdx=hex(ctx.Rdx),ret=hex(ret),bad=bad)
                hits.append(rec)
                if bad or len(hits)<=8 or len(hits)>100:
                    print(rec)
                if bad:
                    # dump caller insn before ret
                    print("  caller bytes", df.read_process_mem(pi.hProcess, ret-8, 16).hex())
                    from capstone import Cs,CS_ARCH_X86,CS_MODE_64
                    md=Cs(CS_ARCH_X86,CS_MODE_64)
                    blob=df.read_process_mem(pi.hProcess, ret-32, 40)
                    for insn in md.disasm(blob, ret-32):
                        mark="<<" if insn.address+insn.size==ret else "  "
                        print(f"  {mark}{insn.address:#x}: {insn.mnemonic} {insn.op_str}")
                    k32.TerminateProcess(pi.hProcess,1); break
        elif code==0x80000004:
            if pending:
                df.patch_byte(pi.hProcess,pending,0xCC)
                pending=None
        elif code in (0xC0000005,0xC0000374):
            ctx=df.get_thread_context(pi.hThread)
            print("FAULT",hex(code),"rip",hex(ctx.Rip),"rcx",hex(ctx.Rcx))
            print("hits",len(hits),"last",hits[-5:])
            k32.TerminateProcess(pi.hProcess,1); break
        else:
            cont=df.DBG_EXCEPTION_NOT_HANDLED
    elif de.dwDebugEventCode==df.EXIT_PROCESS_DEBUG_EVENT:
        print("exit",hex(de.u.ExitProcess.dwExitCode&0xffffffff),"hits",len(hits)); break
    k32.ContinueDebugEvent(de.dwProcessId,de.dwThreadId,cont)
