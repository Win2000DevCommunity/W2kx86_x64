from pathlib import Path
import struct
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

pe=bytearray(Path('build_univ176/cmd_pure_i.exe').read_bytes())
e=struct.unpack_from('<I',pe,0x3c)[0]
num=struct.unpack_from('<H',pe,e+6)[0]
opt=struct.unpack_from('<H',pe,e+20)[0]
sec=e+24+opt
for i in range(num):
    o=sec+i*40
    name=pe[o:o+8].split(b'\0')[0]
    vs,va,rs,rp=struct.unpack_from('<IIII',pe,o+8)
    if name==b'.text':
        tr,text_rp,text_rs=va,rp,rs

app=0x80047f60
sys_va=0x80066884
n=0
for bad,good in [(0x80001b78,app),(0x80001b58,sys_va)]:
    tip=struct.pack('<Q',bad); i=text_rp
    while True:
        at=pe.find(tip,i)
        if at<0 or at>=text_rp+text_rs: break
        pe[at:at+8]=struct.pack('<Q',good); n+=1; i=at+1
print('va',n)

stub_rva=0x3988c
stub=bytearray()
stub+=b'\x48\xbb'+struct.pack('<Q',0x80084590)
stub+=b'\x48\x8b\x1b'
rel=0x26545-(stub_rva+len(stub)+5)
stub+=b'\xe9'+struct.pack('<i', rel)
soff=stub_rva-tr+text_rp
print('before', pe[soff:soff+24].hex())
pe[soff:soff+len(stub)]=stub
print('stub', stub.hex())

joff=0x48701-tr+text_rp
assert pe[joff]==0xe9
struct.pack_into('<i', pe, joff+1, stub_rva-(0x48701+5))
print('jmp retarget', hex(struct.unpack_from('<i',pe,joff+1)[0]))

# verify entry untouched
entry=0x4870e
print('entry', pe[entry-tr+text_rp:entry-tr+text_rp+12].hex())

Path('build_univ176/cmd_pure_j.exe').write_bytes(pe)
print('wrote')