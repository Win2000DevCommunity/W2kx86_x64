from pathlib import Path
import struct
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

pe=bytearray(Path('build_univ176/cmd_pure_g.exe').read_bytes())
e=struct.unpack_from('<I',pe,0x3c)[0]
num=struct.unpack_from('<H',pe,e+6)[0]
opt=struct.unpack_from('<H',pe,e+20)[0]
sec=e+24+opt
for i in range(num):
    o=sec+i*40
    name=pe[o:o+8].split(b'\0')[0]
    vs,va,rs,rp=struct.unpack_from('<IIII',pe,o+8)
    if name==b'.text':
        text_rp,text_va,text_rs=rp,va,rs
        break

fbe2=0x8005bbe2
fbc8=0x8005bbc8
c8d8=0x800588d8

def build_helper():
    h=bytearray()
    h+=b'\x49\xbb'+struct.pack('<Q',fbe2)
    h+=b'\x66\x41\x83\x3b\x00'
    jnz=len(h); h+=b'\x75\x00'
    h+=b'\x65\x48\x8b\x04\x25\x60\x00\x00\x00'
    h+=b'\x48\x8b\x40\x20'
    h+=b'\x48\x8b\x40\x78'
    h+=b'\x48\x85\xc0'
    jz=len(h); h+=b'\x74\x00'
    h+=b'\x48\x89\xc2'
    loop=len(h)
    h+=b'\x66\x83\x3a\x00'
    je0=len(h); h+=b'\x74\x00'
    h+=b'\x66\x83\x3a\x2f'
    jne1=len(h); h+=b'\x75\x00'
    h+=b'\x66\x83\x7a\x02\x63'
    je1=len(h); h+=b'\x74\x00'
    h+=b'\x66\x83\x7a\x02\x43'
    jne2=len(h); h+=b'\x75\x00'
    found=len(h)
    h+=b'\x48\x83\xc2\x04'
    h+=b'\x66\x83\x3a\x20'
    h+=b'\x75\x04'
    h+=b'\x48\x83\xc2\x02'
    h+=b'\x49\xb8'+struct.pack('<Q',fbe2)
    h+=b'\x41\xb9\x00\x01\x00\x00'
    copy=len(h)
    h+=b'\x66\x8b\x0a'
    h+=b'\x66\x41\x89\x08'
    h+=b'\x49\x83\xc0\x02'
    h+=b'\x48\x83\xc2\x02'
    h+=b'\x66\x85\xc9'
    jed=len(h); h+=b'\x74\x00'
    h+=b'\x41\xff\xc9'
    jnec=len(h); h+=b'\x75\x00'
    h+=b'\x66\x41\xc7\x00\x00\x00'
    store=len(h)
    h+=b'\xb8'+struct.pack('<I',fbe2&0xffffffff)
    h+=b'\x49\xbb'+struct.pack('<Q',fbc8)
    h+=b'\x41\x89\x03'
    h+=b'\x49\xbb'+struct.pack('<Q',c8d8)
    h+=b'\x41\x89\x03'
    h+=b'\xc3'
    nxt=len(h)
    h+=b'\x48\x83\xc2\x02'
    jmp=len(h); h+=b'\xeb\x00'
    empty=len(h)
    h+=b'\x49\xbb'+struct.pack('<Q',fbe2)
    h+=b'\x66\x41\xc7\x03\x00\x00'
    h+=b'\xb8'+struct.pack('<I',fbe2&0xffffffff)
    h+=b'\x49\xbb'+struct.pack('<Q',fbc8)
    h+=b'\x41\x89\x03'
    h+=b'\x49\xbb'+struct.pack('<Q',c8d8)
    h+=b'\x41\x89\x03'
    h+=b'\xc3'
    eof=len(h); h+=b'\xc3'
    def pr(a,t): h[a]=(t-(a+1))&0xff
    pr(jnz+1,eof); pr(jz+1,empty); pr(je0+1,empty); pr(jne1+1,nxt)
    pr(je1+1,found); pr(jne2+1,nxt); pr(jed+1,store); pr(jnec+1,copy); pr(jmp+1,loop)
    return bytes(h)

helper=build_helper()
# find pad at end of text raw
blob=pe[text_rp:text_rp+text_rs]
pad=None
run=0
for i in range(len(blob)-1, len(blob)-0x8000, -1):
    if blob[i] in (0,0x90,0xCC):
        run+=1
        if run>=len(helper)+16:
            pad=i
    else:
        run=0
assert pad is not None
print('pad at rva', hex(text_va+pad), 'helper', len(helper))
pe[text_rp+pad:text_rp+pad+len(helper)]=helper
# retarget call at 0x448cb from 0x48530 to new helper
call_off=0x448cb-text_va
assert pe[text_rp+call_off]==0xE8
new_rel=(pad)-(call_off+5)
struct.pack_into('<i', pe, text_rp+call_off+1, new_rel)
print('call retarget rel', hex(new_rel&0xffffffff))
Path('build_univ176/cmd_pure_h.exe').write_bytes(pe)
print('wrote cmd_pure_h.exe')