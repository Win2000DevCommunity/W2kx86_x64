# Verify PEB offsets at runtime via a tiny probe in the child... or just check Windows docs.
# Map 0x48530 to x86
rmap={}
for line in open('build_univ176/rva.txt'):
    p=line.split()
    if len(p)>=2:
        try:
            a,b=int(p[0],16),int(p[1],16)
            if b==0x48530 or abs(b-0x48530)<0x20:
                print('x86 %#x -> pe64 %#x'%(a,b))
        except: pass