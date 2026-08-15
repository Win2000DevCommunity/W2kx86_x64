import ctypes as C, struct, sys, os
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
sys.path.insert(0, ".")
import dbg_fault as df

# verify debs in both
pe=open("build_univ230/cmd_both.exe","rb").read()
e=struct.unpack_from("<I",pe,0x3C)[0]
ns=struct.unpack_from("<H",pe,e+6)[0]; so=struct.unpack_from("<H",pe,e+20)[0]; sec=e+24+so
ib=struct.unpack_from("<Q",pe,e+24+24)[0]
for i in range(ns):
    o=sec+i*40
    if pe[o:o+5]==b".text":
        vs,va,rs,rp=struct.unpack_from("<IIII",pe,o+8); break
md=Cs(CS_ARCH_X86,CS_MODE_64)
print("24a1c:")
for insn in md.disasm(pe[rp+(0x24a17-va):rp+(0x24a17-va)+0x15], ib+0x24a17):
    print(f"  {insn.address:#x}: {insn.mnemonic} {insn.op_str}")

k32 = C.WinDLL("kernel32", use_last_error=True)
df.suppress_fault_ui()
os.chdir("build_univ230")
exe=os.path.abspath("cmd_both.exe")
BP=ib+0x24a9b
si=df.STARTUPINFO(); si.cb=C.sizeof(si); pi=df.PROCESS_INFORMATION()
cmd=C.create_unicode_buffer(f'"{exe}" /c echo w2ktest')
assert k32.CreateProcessW(exe,cmd,None,None,False,df.DEBUG_ONLY_THIS_PROCESS,None,os.getcwd(),C.byref(si),C.byref(pi))
orig=None; de=df.DEBUG_EVENT(); pending=None; n=0
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
            k32.SetThreadContext(pi.hThread,C.byref(ctx)); pending=BP
            h18=struct.unpack("<Q", df.read_process_mem(pi.hProcess,ctx.Rbp+0x18,8))[0]
            ret=struct.unpack("<Q", df.read_process_mem(pi.hProcess,ctx.Rbp+8,8))[0]
            ch=struct.unpack("<I", df.read_process_mem(pi.hProcess,ctx.Rbp-0xc,4))[0]&0xffff
            print(f"n={n} ch={ch:#x} h18={h18:#x} ret={ret:#x}")
            n+=1
            if h18>0x100000000 or n>20:
                k32.TerminateProcess(pi.hProcess,1); break
        elif code==0x80000004:
            if pending: df.patch_byte(pi.hProcess,pending,0xCC); pending=None
        elif code in (0xC0000005,0xC0000374):
            ctx=df.get_thread_context(pi.hThread)
            print("FAULT",hex(code),"rip",hex(ctx.Rip),"rcx",hex(ctx.Rcx),"n",n)
            k32.TerminateProcess(pi.hProcess,1); break
        else:
            if code not in (0x80000003,): cont=df.DBG_EXCEPTION_NOT_HANDLED
    elif de.dwDebugEventCode==df.EXIT_PROCESS_DEBUG_EVENT:
        print("exit",n); break
    k32.ContinueDebugEvent(de.dwProcessId,de.dwThreadId,cont)
