import struct
from pathlib import Path

# confirm IAT 1264 name properly
pe=Path(r'C:\Users\win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU\cmd.exe').read_bytes()
e=struct.unpack_from('<I',pe,0x3c)[0]
num=struct.unpack_from('<H',pe,e+6)[0]
opt=struct.unpack_from('<H',pe,e+20)[0]
sec=e+24+opt
secs=[]
for i in range(num):
    o=sec+i*40
    name=pe[o:o+8].split(b'\0')[0]
    vs,va,rs,rp=struct.unpack_from('<IIII',pe,o+8)
    secs.append((name,va,rp,rs,vs))

def r2o(rva):
    for name,va,rp,rs,vs in secs:
        if va<=rva<va+max(rs,vs): return rp+(rva-va)
    return None

# dump names around 0x1baa0
off=r2o(0x1ba00)
chunk=pe[off:off+0x200]
i=0
while i < len(chunk)-4:
    if chunk[i+2:i+3].isalnum() or chunk[i+2:i+3]==b'_':
        # try parse hint+name
        if chunk[i+1] < 0x20 and 0x20 <= chunk[i+2] < 0x7f:
            nm=chunk[i+2:].split(b'\0')[0]
            if 3 < len(nm) < 40 and all(32<=c<127 for c in nm):
                print(hex(0x1ba00+i), nm)
                i += 2+len(nm)+1
                continue
    i+=1

# data around 0x1fb80 (rva = va 0x1c000 + ?)
# va 0x4ad1fb80 - ib 0x4ad00000 = rva 0x1fb80
# .data va 0x1c000, so offset in data = 0x1fb80-0x1c000 = 0x3b80
# but .data raw only 0x1000! rest is BSS zeros
print('data rva 1fb80 is BSS' if 0x3b80 >= 0x1000 else 'in raw')
# list nearby known from disasm: 1faec, 1fbc8, 21000, 1fae0, 1fae4
for rva in [0x1fae0,0x1fae4,0x1fae8,0x1faec,0x1fb80,0x1fbc8,0x1c8d8,0x21000]:
    print('rva',hex(rva), 'bss' if rva >= 0x1c000+0x1000 else 'raw')

# pe64: what import is at call in Echo - check shim exports / names in binary
pe64=Path('build_univ176/cmd_pure_f.exe').read_bytes()
for nm in [b'_setjmp3', b'setjmp', b'longjmp', b'_setjmp']:
    idx=0; hits=[]
    while True:
        p=pe64.find(nm, idx)
        if p<0: break
        hits.append(hex(p)); idx=p+1
        if len(hits)>5: break
    print(nm, hits)

# check w2kshim for setjmp
shim=Path('build_univ176/w2kshim64.dll').read_bytes()
for nm in [b'_setjmp3', b'setjmp', b'longjmp']:
    print('shim', nm, hex(shim.find(nm)) if shim.find(nm)>=0 else None)