import struct
from pathlib import Path
from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_MODE_32

pe=Path('build_univ176/cmd_pure_f.exe').read_bytes()
e=struct.unpack_from('<I',pe,0x3c)[0]
num=struct.unpack_from('<H',pe,e+6)[0]
opt=struct.unpack_from('<H',pe,e+20)[0]
ib=struct.unpack_from('<Q',pe,e+24+24)[0]
sec=e+24+opt
secs={}
for i in range(num):
    o=sec+i*40
    name=pe[o:o+8].split(b'\0')[0]
    vs,va,rs,rp=struct.unpack_from('<IIII',pe,o+8)
    secs[name]=(va,rp,rs)

# resolve IAT slot 0x84ea0
slot=0x84ea0
for name,(va,rp,rs) in secs.items():
    if va<=slot<va+rs:
        off=rp+(slot-va)
        print('slot in',name.decode(), 'file',hex(off), 'qword',hex(struct.unpack_from('<Q',pe,off)[0]))

# imports
# parse PE64 import dir
opt_magic=struct.unpack_from('<H',pe,e+24)[0]
idd_rva=struct.unpack_from('<I',pe,e+24+112)[0]
print('import dir rva',hex(idd_rva))

def rva_to_off(rva):
    for va,rp,rs in secs.values():
        if va<=rva<va+rs: return rp+(rva-va)
    return None

# walk imports to find which thunk is 0x84ea0
rva=idd_rva
while True:
    off=rva_to_off(rva)
    if off is None: break
    ilt,_,_,name_rva,iat=struct.unpack_from('<IIIII',pe,off)
    if ilt==0 and name_rva==0: break
    dll=pe[rva_to_off(name_rva):].split(b'\0')[0]
    thunk=iat
    while True:
        to=rva_to_off(thunk)
        if to is None: break
        tip=struct.unpack_from('<Q',pe,to)[0]
        if tip==0: break
        if thunk==slot:
            if tip & (1<<63):
                print('ordinal', tip&0xffff, 'dll',dll)
            else:
                no=rva_to_off(tip&0x7fffffff)
                hint,=struct.unpack_from('<H',pe,no)
                nm=pe[no+2:].split(b'\0')[0]
                print('IMPORT', dll, nm, 'hint',hint)
        thunk+=8
    rva+=20

# string at 0x5bb80
sva=0x5bb80
for name,(va,rp,rs) in secs.items():
    if va<=sva<va+rs:
        off=rp+(sva-va)
        print('str', pe[off:off+80])

# x86 disasm 0xadd9
x86=Path(r'C:\Users\win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU\cmd.exe').read_bytes()
e=struct.unpack_from('<I',x86,0x3c)[0]
num=struct.unpack_from('<H',x86,e+6)[0]
opt=struct.unpack_from('<H',x86,e+20)[0]
sec=e+24+opt
for i in range(num):
    o=sec+i*40
    if x86[o:o+5]==b'.text':
        vs,va,rs,rp=struct.unpack_from('<IIII',x86,o+8); xt=x86[rp:rp+rs]; xr=va; break
md=Cs(CS_ARCH_X86, CS_MODE_32)
print('==== x86 0xadd9 ====')
for insn in md.disasm(xt[0xadd9-xr:0xadd9-xr+0xa0], 0xadd9):
    print('  %06x: %s %s'%(insn.address, insn.mnemonic, insn.op_str))

# pe64 path at jne target 0x14e1d and fallthrough
blob=pe[secs[b'.text'][1]:secs[b'.text'][1]+secs[b'.text'][2]]
tr=secs[b'.text'][0]
md64=Cs(CS_ARCH_X86, CS_MODE_64)
print('==== pe64 0x14e1d (jne target) ====')
for insn in md64.disasm(blob[0x14e1d-tr:0x14e1d-tr+0x40], 0x80014e1d):
    print('  %06x: %s %s'%(insn.address-0x80000000, insn.mnemonic, insn.op_str))