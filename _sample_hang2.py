import ctypes, ctypes.wintypes as w, pathlib, struct, subprocess, time
from ctypes import byref, c_size_t, create_string_buffer, windll
import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

PROCESS_QUERY_INFORMATION=0x0400; PROCESS_VM_READ=0x0010
TH32CS_SNAPTHREAD=4; THREAD_GET_CONTEXT=8; THREAD_SUSPEND_RESUME=2
CONTEXT_CONTROL=0x100001; CONTEXT_INTEGER=0x100002

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

exe=str(pathlib.Path("build_univ65/cmd_heal.exe").resolve())
p=subprocess.Popen([exe,"/c","echo w2ktest"],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,cwd=str(pathlib.Path(exe).parent),creationflags=0x08000000)
time.sleep(1.2)
k32=windll.kernel32; ntdll=windll.ntdll
h=k32.OpenProcess(PROCESS_QUERY_INFORMATION|PROCESS_VM_READ,False,p.pid)
pbi=PBI(); ntdll.NtQueryInformationProcess(h,0,byref(pbi),ctypes.sizeof(pbi),None)
ib=struct.unpack_from("<Q",rpm(h,pbi.PebBaseAddress+0x10,8))[0]
pe=pefile.PE(exe); print(f"pid={p.pid} liveIB={ib:#x} fileIB={pe.OPTIONAL_HEADER.ImageBase:#x} SizeOfImage={pe.OPTIONAL_HEADER.SizeOfImage:#x}")
snap=k32.CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD,0)
te=THREADENTRY32(); te.dwSize=ctypes.sizeof(te); tids=[]
ok=k32.Thread32First(snap,byref(te))
while ok:
    if te.th32OwnerProcessID==p.pid: tids.append(te.th32ThreadID)
    ok=k32.Thread32Next(snap,byref(te))
k32.CloseHandle(snap)
md=Cs(CS_ARCH_X86,CS_MODE_64)
for tid in tids[:5]:
    th=k32.OpenThread(THREAD_GET_CONTEXT|THREAD_SUSPEND_RESUME,False,tid)
    k32.SuspendThread(th)
    buf=(ctypes.c_byte*1232)(); struct.pack_into("<I",buf,0x30,CONTEXT_CONTROL|CONTEXT_INTEGER)
    ok=k32.GetThreadContext(th,buf)
    rip=struct.unpack_from("<Q",buf,0xF8)[0]; rsp=struct.unpack_from("<Q",buf,0x98)[0]
    rcx=struct.unpack_from("<Q",buf,0x80)[0]; rdx=struct.unpack_from("<Q",buf,0x88)[0]
    r8=struct.unpack_from("<Q",buf,0xB8)[0]; r9=struct.unpack_from("<Q",buf,0xC0)[0]
    rva=rip-ib; in_img=ib<=rip<ib+pe.OPTIONAL_HEADER.SizeOfImage
    print(f"tid={tid} RIP={rip:#x} RVA={rva:#x} in_img={in_img} RSP={rsp:#x} RCX={rcx:#x} RDX={rdx:#x} R8={r8:#x} R9={r9:#x}")
    code=rpm(h,rip,32)
    if code:
        for i in md.disasm(code,rip):
            print(f"  {i.address-ib:#x}: {i.mnemonic} {i.op_str}"); break
        else:
            print("  bytes", code[:16].hex())
    stk=rpm(h,rsp,160); rets=[]
    for i in range(0,len(stk),8):
        v=struct.unpack_from("<Q",stk,i)[0]
        if ib<=v<ib+pe.OPTIONAL_HEADER.SizeOfImage: rets.append(f"{v-ib:#x}")
    print("  imgrets", " ".join(rets[:16]))
    k32.ResumeThread(th); k32.CloseHandle(th)
p.kill(); p.wait()
