from pathlib import Path
import struct
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

# Start from i.exe again (good entry)
pe=bytearray(Path('build_univ176/cmd_pure_i.exe').read_bytes())
e=struct.unpack_from('<I',pe,0x3c)[0]
num=struct.unpack_from('<H',pe,e+6)[0]
opt=struct.unpack_from('<H',pe,e+20)[0]
entry_rva=struct.unpack_from('<I',pe,e+24+16)[0]
print('AddressOfEntryPoint', hex(entry_rva))
sec=e+24+opt
for i in range(num):
    o=sec+i*40
    name=pe[o:o+8].split(b'\0')[0]
    vs,va,rs,rp=struct.unpack_from('<IIII',pe,o+8)
    if name==b'.text':
        tr,text_rp,text_rs=va,rp,rs
        blob=memoryview(pe)[text_rp:text_rp+text_rs]

# Find Application / System in .data preferentially
app=sys_va=None
app_s=b'A\x00p\x00p\x00l\x00i\x00c\x00a\x00t\x00i\x00o\x00n\x00\x00\x00'
sys_s=b'S\x00y\x00s\x00t\x00e\x00m\x00\x00\x00'
for i in range(num):
    o=sec+i*40
    name=pe[o:o+8].split(b'\0')[0]
    vs,va,rs,rp=struct.unpack_from('<IIII',pe,o+8)
    chunk=bytes(pe[rp:rp+rs])
    for needle, label in ((app_s,'app'),(sys_s,'sys')):
        idx=chunk.find(needle)
        if idx>=0:
            v=0x80000000+va+idx
            print(label, 'in', name, hex(v))
            if label=='app' and app is None: app=v
            if label=='sys' and sys_va is None: sys_va=v
print('using app', hex(app), 'sys', hex(sys_va) if sys_va else None)

n=0
for bad,good in [(0x80001b78, app), (0x80001b58, sys_va)]:
    if not good: continue
    tip=struct.pack('<Q', bad)
    i=text_rp
    while True:
        at=pe.find(tip, i)
        if at<0 or at>=text_rp+text_rs: break
        pe[at:at+8]=struct.pack('<Q', good); n+=1
        i=at+1
print('va patches', n)

# Find pad NOT near entry (entry ~0x4870e)
entry_off=entry_rva-tr
stub_len=18
pad=None
run=0
for i in range(len(blob)-1, max(0,len(blob)-0x10000), -1):
    # skip entry stub region
    if abs(i - entry_off) < 0x40:
        run=0; continue
    if blob[i] in (0,0x90,0xCC):
        run+=1
        if run>=stub_len+8:
            pad=i
    else:
        run=0
print('pad rva', hex(tr+pad) if pad is not None else None, 'entry', hex(entry_rva))
assert pad is not None
stub_rva=tr+pad
stub=bytearray()
stub+=b'\x48\xbb'+struct.pack('<Q',0x80084590)
stub+=b'\x48\x8b\x1b'
rel=0x26545-(stub_rva+len(stub)+5)
stub+=b'\xe9'+struct.pack('<i', rel)
pe[text_rp+pad:text_rp+pad+len(stub)]=stub

# retarget trampoline jmp at 0x48701
joff=0x48701-tr+text_rp
assert pe[joff]==0xe9
struct.pack_into('<i', pe, joff+1, stub_rva-(0x48701+5))
print('stub at', hex(stub_rva), 'jmp from 48701 rel', hex(struct.unpack_from('<i',pe,joff+1)[0]&0xffffffff))

# verify entry intact
md=Cs(CS_ARCH_X86, CS_MODE_64)
print('entry:')
for insn in md.disasm(bytes(pe[text_rp+entry_off:text_rp+entry_off+20]), 0x80000000+entry_rva):
    print(' ', insn.mnemonic, insn.op_str)

Path('build_univ176/cmd_pure_j.exe').write_bytes(pe)
print('wrote j')