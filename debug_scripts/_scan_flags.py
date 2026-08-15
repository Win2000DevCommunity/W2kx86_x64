from pathlib import Path
import struct
pe=Path('build_univ176/cmd_pure.exe').read_bytes()
e=struct.unpack_from('<I',pe,0x3c)[0]
num=struct.unpack_from('<H',pe,e+6)[0]
opt=struct.unpack_from('<H',pe,e+20)[0]
sec=e+24+opt
blob=None; text_rva=0
for i in range(num):
    o=sec+i*40
    name=pe[o:o+8].split(b'\0')[0]
    if name==b'.text':
        vs,rva,rawsz,rawptr=struct.unpack_from('<IIII',pe,o+8)
        blob=pe[rawptr:rawptr+rawsz]; text_rva=rva
        break
cmps=[(bytes([0x85,0xc0]),2),(bytes([0x39,0xd8]),2),(bytes([0x3b,0xc3]),2),(bytes([0x83,0xf8,0x00]),3),(bytes([0x39,0xc3]),2)]
patterns=[]
i=0
while i < len(blob)-14:
    for cmpb,cmplen in cmps:
        if blob[i:i+cmplen]==cmpb:
            j=i+cmplen
            if j+4<=len(blob) and blob[j:j+3]==bytes([0x48,0x83,0xc4]):
                imm=blob[j+3]; k=j+4
                if k+5<len(blob) and blob[k]==0x0f and 0x80<=blob[k+1]<=0x8f:
                    patterns.append((text_rva+i, 'near', cmpb.hex(), imm, blob[k+1]))
                elif k<len(blob) and 0x70<=blob[k]<=0x7f:
                    patterns.append((text_rva+i, 'short', cmpb.hex(), imm, blob[k]))
            break
    i+=1
print('found', len(patterns))
for p in patterns:
    print('  rva=%#x %s cmp=%s add=%#x jcc=%#x' % p)