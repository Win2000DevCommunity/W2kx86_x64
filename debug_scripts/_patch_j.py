from pathlib import Path
import struct

pe=bytearray(Path('build_univ176/cmd_pure_i.exe').read_bytes())
e=struct.unpack_from('<I',pe,0x3c)[0]
num=struct.unpack_from('<H',pe,e+6)[0]
opt=struct.unpack_from('<H',pe,e+20)[0]
sec=e+24+opt
app=None; sys_va=None
for i in range(num):
    o=sec+i*40
    name=pe[o:o+8].split(b'\0')[0]
    vs,va,rs,rp=struct.unpack_from('<IIII',pe,o+8)
    if name==b'.text':
        tr,text_rp,text_rs=va,rp,rs
app_s=b'A\x00p\x00p\x00l\x00i\x00c\x00a\x00t\x00i\x00o\x00n\x00'
sys_s=b'S\x00y\x00s\x00t\x00e\x00m\x00\x00\x00'
for needle, var in ((app_s,'app'),(sys_s,'sys')):
    idx=pe.find(needle)
    for i in range(num):
        o=sec+i*40
        name=pe[o:o+8].split(b'\0')[0]
        vs,va,rs,rp=struct.unpack_from('<IIII',pe,o+8)
        if rp<=idx<rp+rs:
            v=0x80000000+va+(idx-rp)
            if var=='app': app=v
            else: sys_va=v
            print(var, hex(v), name)
n=0
for bad,good in [(0x80001b78, app), (0x80001b58, sys_va)]:
    tip=struct.pack('<Q', bad)
    i=0
    while True:
        at=pe.find(tip, i)
        if at<0: break
        if text_rp <= at < text_rp+text_rs:
            pe[at:at+8]=struct.pack('<Q', good); n+=1
        i=at+1
print('va patches', n)

stub_rva=0x48706
stub=bytearray()
stub+=b'\x48\xbb'+struct.pack('<Q',0x80084590)
stub+=b'\x48\x8b\x1b'
rel=0x26545-(stub_rva+len(stub)+5)
stub+=b'\xe9'+struct.pack('<i', rel)
soff=stub_rva-tr+text_rp
# ensure room
if soff+len(stub) > text_rp+text_rs:
    raise SystemExit('no room')
pe[soff:soff+len(stub)]=stub
joff=0x48701-tr+text_rp
assert pe[joff]==0xe9, pe[joff:joff+5].hex()
struct.pack_into('<i', pe, joff+1, stub_rva-(0x48701+5))
print('stub', hex(stub_rva), stub.hex())
Path('build_univ176/cmd_pure_j.exe').write_bytes(pe)
print('wrote')