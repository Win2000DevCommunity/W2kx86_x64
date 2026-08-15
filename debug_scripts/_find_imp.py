import struct
from pathlib import Path

pe=Path(r'C:\Users\win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU\cmd.exe').read_bytes()
e=struct.unpack_from('<I',pe,0x3c)[0]
num=struct.unpack_from('<H',pe,e+6)[0]
opt=struct.unpack_from('<H',pe,e+20)[0]
ib=struct.unpack_from('<I',pe,e+24+28)[0]
idd=struct.unpack_from('<I',pe,e+24+96)[0]
print('ib',hex(ib),'idd',hex(idd),'opt',opt)
sec=e+24+opt
secs=[]
for i in range(num):
    o=sec+i*40
    name=pe[o:o+8].split(b'\0')[0]
    vs,va,rs,rp=struct.unpack_from('<IIII',pe,o+8)
    print(name, 'va',hex(va),'vs',hex(vs),'rs',hex(rs),'rp',hex(rp))
    secs.append((name,va,rp,rs,vs))

def r2o(rva):
    for name,va,rp,rs,vs in secs:
        if va<=rva<va+max(rs,vs):
            return rp+(rva-va)
    return None

# direct: thunk rva 0x1264 - which section?
print('r2o 1264', r2o(0x1264))
# read import lookup at IAT 0x1264
off=r2o(0x1264)
print('iat dword', hex(struct.unpack_from('<I',pe,off)[0]))
tip=struct.unpack_from('<I',pe,off)[0]
print('tip name off', r2o(tip), pe[r2o(tip):r2o(tip)+20] if r2o(tip) else None)

# walk all imports safely
rva=idd
seen=0
while seen<50:
    off=r2o(rva)
    if off is None:
        print('bad idd off',hex(rva)); break
    ilt,tim,fwd,name_rva,iat=struct.unpack_from('<IIIII',pe,off)
    if name_rva==0: break
    dll=pe[r2o(name_rva):].split(b'\0')[0]
    thunk=iat
    while True:
        to=r2o(thunk)
        if to is None: break
        tip=struct.unpack_from('<I',pe,to)[0]
        if tip==0: break
        if tip & 0x80000000:
            nm=b'ord%d'%(tip&0xffff)
        else:
            no=r2o(tip)
            nm=pe[no+2:].split(b'\0')[0] if no else b'?'
        if thunk==0x1264 or nm in (b'wcschr',b'strchr',b'_wcsicmp',b'lstrcmpW'):
            print('IMP',dll,nm,'thunk',hex(thunk))
        thunk+=4
    rva+=20
    seen+=1
print('done imports',seen)