import struct, pathlib, subprocess, sys
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
import pefile

pe_path = pathlib.Path("build_univ258/cmd_pure.exe")
pe = pefile.PE(str(pe_path))
md = Cs(CS_ARCH_X86, CS_MODE_64)
print("=== 427F0-428E0 ===")
for i in md.disasm(pe.get_data(0x427F0, 0xF0), 0x800427F0):
    print(f"  {i.address-0x80000000:06X}: {i.mnemonic} {i.op_str}")

# Fix: find add rsp,8 before jmp that leads to sticky cave / success epi
data = bytearray(pe_path.read_bytes())
e = struct.unpack_from("<I", data, 0x3C)[0]
ns = struct.unpack_from("<H", data, e+6)[0]; so=struct.unpack_from("<H", data, e+20)[0]; sec=e+24+so
for i in range(ns):
    o=sec+i*40
    if data[o:o+5]==b".text":
        vs,va,rs,rp=struct.unpack_from("<IIII", data, o+8); break
blob=bytearray(data[rp:rp+rs])
# Pattern: 48 83 c4 08 e9  (add rsp,8; jmp)
fixed=0
i=0
while True:
    at=blob.find(bytes.fromhex("4883c408e9"), i)
    if at<0: break
    # retarget any E9 that lands on `at` to `at+4` (the jmp)
    for j in range(max(0,at-0x180), at-5):
        if blob[j]!=0xE9: continue
        rel=struct.unpack_from("<i", blob, j+1)[0]
        if j+5+rel==at:
            # skip if preceded by push args
            pre=bytes(blob[max(0,j-8):j])
            if pre and 0x50<=pre[-1]<=0x57: continue
            struct.pack_into("<i", blob, j+1, (at+4)-(j+5))
            fixed+=1
            print("retarget", hex(j+va), "-> skip addrsp")
    i=at+1
print("fixed", fixed)
data[rp:rp+rs]=blob
outp=pathlib.Path("build_univ258/cmd_probe_rjoin.exe")
outp.write_bytes(data)
p=subprocess.Popen([sys.executable,"dbg_fault.py",str(outp),"/c","echo","w2ktest"],stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
try:
    out,_=p.communicate(timeout=12); st=f"DONE exit={p.returncode}"
except subprocess.TimeoutExpired:
    p.kill(); out,_=p.communicate(); st="TIMEOUT"
print(st)
print(out.decode("utf-8","replace").encode("ascii","replace").decode()[:1500])
