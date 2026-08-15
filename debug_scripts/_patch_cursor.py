from pathlib import Path
import struct

def patch_pe(path_in, path_out):
    pe=bytearray(Path(path_in).read_bytes())
    e=struct.unpack_from('<I',pe,0x3c)[0]
    num=struct.unpack_from('<H',pe,e+6)[0]
    opt=struct.unpack_from('<H',pe,e+20)[0]
    sec=e+24+opt
    for i in range(num):
        o=sec+i*40
        if pe[o:o+5]==b'.text':
            vs,va,rs,rp=struct.unpack_from('<IIII',pe,o+8)
            break
    blob=memoryview(pe)[rp:rp+rs]
    # Replace wrong data VAs in helper region
    n=0
    for old,new in [
        (0x8005dbe2, 0x8005bbe2),
        (0x8005dbc8, 0x8005bbc8),
    ]:
        tip=struct.pack('<Q', old)
        newt=struct.pack('<Q', new)
        # also 32-bit immediates for mov eax, imm32
        tip32=struct.pack('<I', old & 0xffffffff)
        new32=struct.pack('<I', new & 0xffffffff)
        i=0
        while True:
            j=pe.find(tip, i)
            if j<0: break
            # only patch inside .text
            if rp <= j < rp+rs:
                pe[j:j+8]=newt; n+=1
            i=j+1
        i=0
        while True:
            j=pe.find(tip32, i)
            if j<0: break
            if rp <= j < rp+rs:
                # avoid accidental patches: require prior B8 (mov eax,imm32) or similar
                if pe[j-1]==0xB8 or (j>=2 and pe[j-2:j]==b'\x49\xb8') or (j>=2 and pe[j-2:j]==b'\x49\xbb'):
                    pe[j:j+4]=new32; n+=1
                elif pe[j-1]==0xB8:
                    pe[j:j+4]=new32; n+=1
            i=j+1
    # Also fix getchar post-refill: at 0x448d0 mov ecx,eax (89 c1) followed by nops
    # Replace with movabs r11,fbc8; mov ecx,[r11] if enough nops
    off=0x448d0 - va + rp
    if pe[off:off+2]==b'\x89\xc1':
        # need 13 bytes: 49 bb <8> 41 8b 0b
        span=2
        while pe[off+span]==0x90: span+=1
        if span>=13:
            patch=b'\x49\xbb'+struct.pack('<Q',0x8005bbc8)+b'\x41\x8b\x0b'
            patch=patch+b'\x90'*(span-len(patch))
            pe[off:off+span]=patch
            n+=1
            print('patched getchar reload, span', span)
    Path(path_out).write_bytes(pe)
    print('patches', n, '->', path_out)

patch_pe('build_univ176/cmd_pure_f.exe', 'build_univ176/cmd_pure_g.exe')