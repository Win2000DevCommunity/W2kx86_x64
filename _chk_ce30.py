import struct, pathlib
from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_MODE_32
md=Cs(CS_ARCH_X86, CS_MODE_64)
p=pathlib.Path("build_univ230/cmd_fix20.exe"); pe=p.read_bytes()
e=struct.unpack_from("<I",pe,0x3C)[0]
ib=struct.unpack_from("<Q",pe,e+0x30)[0]
ns=struct.unpack_from("<H",pe,e+6)[0]; so=struct.unpack_from("<H",pe,e+20)[0]; sec=e+24+so
secs=[]
for i in range(ns):
    o=sec+i*40
    nm=pe[o:o+8].split(b"\0")[0].decode()
    vs,va,rs,rp=struct.unpack_from("<IIII",pe,o+8)
    secs.append((nm,va,vs,rp,rs))
    if nm==".text": tva,trp,trs=va,rp,rs
def r2o(rva):
    for nm,va,vs,rp,rs in secs:
        if va<=rva<va+max(vs,rs): return rp+(rva-va)
    return None
# import table
imp=struct.unpack_from("<I",pe,e+0x18+0x78)[0]
names={}
o=r2o(imp)
while True:
    ok,tstamp,fc,nrva,fthunk=struct.unpack_from("<IIIII",pe,o)
    if ok==0 and nrva==0: break
    dll=pe[r2o(nrva):].split(b"\0")[0].decode()
    to=r2o(ok or fthunk); ft=r2o(fthunk)
    k=0
    while True:
        v=struct.unpack_from("<Q",pe,to+k*8)[0]
        if v==0: break
        if not (v>>63):
            nm=pe[r2o(v)+2:].split(b"\0")[0].decode()
            names[ib+fthunk+k*8]=f"{dll}!{nm}"
        k+=1
    o+=20
print("==== cd80..ce60 ====")
for insn in md.disasm(pe[trp+(0xcd80-tva):trp+(0xce60-tva)], ib+0xcd80):
    extra=""
    if insn.mnemonic=="movabs" and insn.op_str.count("0x"):
        try:
            v=int(insn.op_str.split(",")[1].strip(),16)
            if v in names: extra=f"   <- {names[v]}"
        except: pass
    print(f"  {insn.address:#x}: {insn.mnemonic} {insn.op_str}{extra}")
