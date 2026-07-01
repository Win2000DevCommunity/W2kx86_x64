import pefile
exe=r"build_out20\cmd_pure.exe"
pe=pefile.PE(exe); data=bytes(pe.get_memory_mapped_image())
sig1=b"\x3d\x00\x10\x00\x00\x51\x48\x8d\x4c\x24\x08"
sig2=b"\x51\x3d\x00\x10\x00\x00\x48\x8d\x4c\x24\x08"
loop=b"\x2d\x00\x10\x00\x00"
for nm,s in (("sig1",sig1),("sig2",sig2)):
    i=0
    while True:
        j=data.find(s,i)
        if j<0: break
        has_loop = data.find(loop,j,j+0x40)!=-1
        print(nm,"at %x  loop_within=%s"%(j,has_loop))
        i=j+1
# also bare cmp eax,0x1000 occurrences
i=0; cnt=0
while True:
    j=data.find(b"\x3d\x00\x10\x00\x00",i)
    if j<0: break
    cnt+=1; i=j+1
print("bare cmp eax,0x1000 count:",cnt)
print("@0x32001:",data[0x32001:0x32001+12].hex())
print("@0x30fbc:",data[0x30fbc:0x30fbc+12].hex())
