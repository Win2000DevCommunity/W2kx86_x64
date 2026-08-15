from pathlib import Path
import struct

def patch_blob(blob):
    fixed=0; i=0
    out=bytearray(blob)
    while i < len(out)-12:
        cmpb=out[i:i+2]
        if (cmpb in (b'\x39\xd8', b'\x85\xc0')
                and out[i+2:i+5]==b'\x48\x83\xc4'
                and out[i+6]==0x0f and 0x80<=out[i+7]<=0x8f):
            imm=out[i+5:i+6]; jcc=out[i+6:i+8]; rel=out[i+8:i+12]
            out[i:i+12]=b'\x48\x83\xc4'+imm+b'\x85\xc0'+jcc+rel
            fixed+=1; i+=12; continue
        i+=1
    return bytes(out), fixed

pe=bytearray(Path('build_univ176/cmd_pure.exe').read_bytes())
e=struct.unpack_from('<I',pe,0x3c)[0]
num=struct.unpack_from('<H',pe,e+6)[0]
opt=struct.unpack_from('<H',pe,e+20)[0]
sec=e+24+opt
for i in range(num):
    o=sec+i*40
    name=bytes(pe[o:o+8]).split(b'\0')[0]
    if name==b'.text':
        vs,rva,rawsz,rawptr=struct.unpack_from('<IIII',pe,o+8)
        blob,n=patch_blob(pe[rawptr:rawptr+rawsz])
        pe[rawptr:rawptr+rawsz]=blob
        print('patched', n, 'sites in .text')
        break
Path('build_univ176/cmd_pure_f.exe').write_bytes(pe)
print('wrote cmd_pure_f.exe')