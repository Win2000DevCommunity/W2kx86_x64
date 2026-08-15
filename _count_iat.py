import pefile, struct
pe = pefile.PE("build_univ258/cmd_probe_wfs.exe")
# count refs to 84e78 vs 845f0
data = pe.get_memory_mapped_image()
for name, rva in [("longjmp",0x84e78),("WFS",0x845f0)]:
    hits=[]
    pat=struct.pack('<Q', 0x80000000+rva)
    off=0
    while True:
        i=data.find(pat, off)
        if i<0: break
        hits.append(i)
        off=i+1
    print(name, [hex(h) for h in hits[:20]], 'count', len(hits))

# check 458B3 and 459C1 raw
print('458AF', pe.get_data(0x458AF, 16).hex())
print('459BE', pe.get_data(0x459BE, 16).hex())
print('459C7', pe.get_data(0x459C7, 8).hex())
print('4599A', pe.get_data(0x4599A, 8).hex())
