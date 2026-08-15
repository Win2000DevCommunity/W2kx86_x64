import ctypes, ctypes.wintypes as w, pathlib, struct, subprocess, time, sys
from ctypes import byref, c_size_t, create_string_buffer, windll
sys.path.insert(0,".")
from dbg_fault import CONTEXT, CONTEXT_FULL, suppress_fault_ui
suppress_fault_ui()

class THREADENTRY32(ctypes.Structure):
    _fields_=[("dwSize",w.DWORD),("cntUsage",w.DWORD),("th32ThreadID",w.DWORD),
              ("th32OwnerProcessID",w.DWORD),("tpBasePri",ctypes.c_long),
              ("tpDeltaPri",ctypes.c_long),("dwFlags",w.DWORD)]
class PBI(ctypes.Structure):
    _fields_=[("a",ctypes.c_void_p),("PebBaseAddress",ctypes.c_void_p),
              ("b",ctypes.c_void_p*2),("pid",ctypes.c_void_p),("c",ctypes.c_void_p)]

def rpm(h,addr,n):
    buf=create_string_buffer(n); got=c_size_t()
    ok=windll.kernel32.ReadProcessMemory(h,ctypes.c_void_p(addr),buf,n,byref(got))
    return buf.raw[:got.value] if ok else b""

exe=str(pathlib.Path("build_univ212/cmd_pure.exe").resolve())
cwd=str(pathlib.Path("build_univ212").resolve())
p=subprocess.Popen([exe,"/c","echo","w2ktest"], stdin=subprocess.DEVNULL,
                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=cwd,
                   creationflags=0x08000000)
time.sleep(2.0)
k32=windll.kernel32; ntdll=windll.ntdll
h=k32.OpenProcess(0x1F0FFF, False, p.pid)
pbi=PBI(); ntdll.NtQueryInformationProcess(h,0,byref(pbi),ctypes.sizeof(pbi),None)
ib=struct.unpack_from("<Q", rpm(h, pbi.PebBaseAddress+0x10, 8))[0]
print("ib", hex(ib))
for name,off in [("c8d8",0x588d8),("fbc8",0x5bbc8),("sticky",0x5be00),("fae0",0x5bae0)]:
    print(name, hex(struct.unpack_from("<I", rpm(h, ib+off, 4))[0]))
raw=rpm(h, ib+0x5bbe2, 64)
chars=[]
for i in range(0,48,2):
    ch=struct.unpack_from("<H",raw,i)[0]
    if ch==0: chars.append("[0]"); break
    chars.append(chr(ch) if 32<=ch<127 else "[%#x]"%ch)
print("fbe2", "".join(chars), "hex", raw[:32].hex())
c8=struct.unpack_from("<I", rpm(h, ib+0x588d8, 4))[0]
if c8:
    raw=rpm(h, c8, 80)
    chars=[]
    for i in range(0,60,2):
        ch=struct.unpack_from("<H",raw,i)[0]
        if ch==0: break
        chars.append(chr(ch) if 32<=ch<127 else "[%#x]"%ch)
    print("buf@c8", hex(c8), "".join(chars))

snap=k32.CreateToolhelp32Snapshot(4,0)
te=THREADENTRY32(); te.dwSize=ctypes.sizeof(te); tids=[]
ok=k32.Thread32First(snap, byref(te))
while ok:
    if te.th32OwnerProcessID==p.pid: tids.append(te.th32ThreadID)
    ok=k32.Thread32Next(snap, byref(te))
k32.CloseHandle(snap)
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
md=Cs(CS_ARCH_X86,CS_MODE_64)
for n in range(10):
    th=k32.OpenThread(0x1F03FF, False, tids[0])
    k32.SuspendThread(th)
    ctx=CONTEXT(); ctx.ContextFlags=CONTEXT_FULL
    k32.GetThreadContext(th, byref(ctx))
    rva=ctx.Rip-ib
    code=rpm(h, ctx.Rip, 16)
    ins=""
    for i in md.disasm(code, ctx.Rip):
        ins="%s %s" % (i.mnemonic, i.op_str); break
    print("#%d RVA=%#x RAX=%#x RCX=%#x | %s" % (n, rva, ctx.Rax&0xffffffff, ctx.Rcx, ins))
    k32.ResumeThread(th); k32.CloseHandle(th)
    time.sleep(0.2)
p.kill(); p.wait()
