from pathlib import Path
import struct
pe=Path('build_univ176/cmd_pure_f.exe').read_bytes()
e=struct.unpack_from('<I',pe,0x3c)[0]
num=struct.unpack_from('<H',pe,e+6)[0]
opt=struct.unpack_from('<H',pe,e+20)[0]
sec=e+24+opt
for i in range(num):
    o=sec+i*40
    if pe[o:o+5]==b'.text':
        vs,va,rs,rp=struct.unpack_from('<IIII',pe,o+8)
        blob=pe[rp:rp+rs]; break

def count(va):
    tip=struct.pack('<Q', va)
    n=0; i=0
    while True:
        j=blob.find(tip,i)
        if j<0: break
        n+=1; i=j+1
    return n

for va in [0x8005bbc8,0x8005dbc8,0x8005bbe2,0x8005dbe2,0x800588d8,0x8005c8d8]:
    print(hex(va), 'hits', count(va))

# x86 data offsets
print('correct offsets from .data:')
print('fbc8', hex(0x1fbc8-0x1c000))
print('fbe2', hex(0x1fbe2-0x1c000))
print('c8d8', hex(0x1c8d8-0x1c000))
print('pe64 .data 0x58000 + 0x3bc8 =', hex(0x58000+0x3bc8))
print('pe64 .data 0x58000 + 0x3be2 =', hex(0x58000+0x3be2))