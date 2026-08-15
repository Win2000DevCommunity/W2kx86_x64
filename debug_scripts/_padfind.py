from pathlib import Path
import struct
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

pe=bytearray(Path('build_univ176/cmd_pure_i.exe').read_bytes())
e=struct.unpack_from('<I',pe,0x3c)[0]
num=struct.unpack_from('<H',pe,e+6)[0]
opt=struct.unpack_from('<H',pe,e+20)[0]
entry_rva=struct.unpack_from('<I',pe,e+24+16)[0]
sec=e+24+opt
for i in range(num):
    o=sec+i*40
    name=pe[o:o+8].split(b'\0')[0]
    vs,va,rs,rp=struct.unpack_from('<IIII',pe,o+8)
    print(name, 'va',hex(va),'vs',hex(vs),'rs',hex(rs),'rp',hex(rp))
    if name==b'.text':
        tr,text_rp,text_rs,text_vs,text_o=va,rp,rs,vs,o

# Use oneshot helper pad from earlier h build - region after helper at ~0x48717
# In i.exe the oneshot was at some pad - find the one-shot signature
sig=b'\x49\xbb'+struct.pack('<Q',0x8005bbe2)+b'\x66\x41\x83\x3b\x00'
at=pe.find(sig)
print('oneshot at file', hex(at) if at>=0 else None, 'rva', hex(tr+(at-text_rp)) if at>=0 else None)

# Find System in .rsrc
sys_s=b'S\x00y\x00s\x00t\x00e\x00m\x00\x00\x00'
app_s=b'A\x00p\x00p\x00l\x00i\x00c\x00a\x00t\x00i\x00o\x00n\x00'
app=sys_va=None
for i in range(num):
    o=sec+i*40
    name=pe[o:o+8].split(b'\0')[0]
    vs,va,rs,rp=struct.unpack_from('<IIII',pe,o+8)
    chunk=bytes(pe[rp:rp+rs])
    if name==b'.rsrc' or name==b'.data':
        for needle,label in ((app_s,'app'),(sys_s,'sys')):
            idx=chunk.find(needle)
            if idx>=0:
                v=0x80000000+va+idx
                print('prefer', label, name, hex(v))
                if label=='app': app=v
                else: sys_va=v
# fallback text
if app is None:
    idx=pe.find(app_s); app=0x80000000+tr+(idx-text_rp)
if sys_va is None:
    # search all
    for i in range(num):
        o=sec+i*40
        name=pe[o:o+8].split(b'\0')[0]
        vs,va,rs,rp=struct.unpack_from('<IIII',pe,o+8)
        idx=bytes(pe[rp:rp+rs]).find(sys_s)
        if idx>=0 and name==b'.rsrc':
            sys_va=0x80000000+va+idx; break
print('final app',hex(app),'sys',hex(sys_va))

# Patch VAs
n=0
for bad,good in [(0x80001b78,app),(0x80001b58,sys_va)]:
    tip=struct.pack('<Q',bad); i=text_rp
    while True:
        at=pe.find(tip,i)
        if at<0 or at>=text_rp+text_rs: break
        pe[at:at+8]=struct.pack('<Q',good); n+=1; i=at+1
print('va',n)

# Place stub by extending .text raw into file alignment gap if any
# Check next section pointer
next_rp=text_rp+text_rs
gap=0
for i in range(num):
    o=sec+i*40
    vs,va,rs,rp=struct.unpack_from('<IIII',pe,o+8)
    if rp>text_rp:
        gap=rp-(text_rp+text_rs)
        print('gap to next', gap, 'next rp', hex(rp))
        break

# Put stub at end of virtual text in the oneshot area: find CC/00 run before entry
blob=pe[text_rp:text_rp+text_rs]
pad=None; run=0
for i in range(0, entry_rva-tr-0x20):
    if blob[i] in (0,0x90,0xCC):
        run+=1
        if run>=24: pad=i-run+1
    else:
        run=0
print('early pad', hex(tr+pad) if pad is not None else None)

# Alternative: overwrite call rbx at 2656f by expanding backwards into mov [rsp+30],rax
# Replace:
#   48 89 44 24 30   mov [rsp+0x30], rax
#   ff d3             call rbx
# With stub call via e8 to our code placed at oneshot's trailing nops after helper

# Find oneshot helper end (ret c3) after sig
if at and at>0:
    helper_rva=tr+(at-text_rp)
    # helper ~216 bytes from earlier
    # place stub AFTER oneshot helper
    stub_rva=helper_rva+220
    print('try stub after oneshot', hex(stub_rva))
    soff=stub_rva-tr+text_rp
    # ensure mostly nop/zero
    region=pe[soff:soff+24]
    print('region', region.hex())

stub=bytearray()
stub+=b'\x48\xbb'+struct.pack('<Q',0x80084590)
stub+=b'\x48\x8b\x1b'
stub+=b'\xe9'+struct.pack('<i', 0x26545-(0))  # fill later

# Use space at 0x48717 from first oneshot in h - check i.exe content there  
print('48706', bytes(pe[0x48706-tr+text_rp:0x48706-tr+text_rp+32]).hex())
print('entry bytes', bytes(pe[entry_rva-tr+text_rp:entry_rva-tr+text_rp+16]).hex())