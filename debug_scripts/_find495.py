import pefile, struct
pe = pefile.PE("build_univ258/cmd_probe_jcc.exe")
# search for 0x495098 as imm32 or in data
img = pe.get_memory_mapped_image()
pat = struct.pack('<I', 0x495098)
hits=[]
off=0
while True:
    i=img.find(pat, off)
    if i<0: break
    hits.append(i); off=i+1
print('hits of 495098', [hex(h) for h in hits[:20]], 'count', len(hits))
# Also 0x800495098 truncated?
# Check string at various
for rva in [0x495098, 0x95098, 0x49800]:
    try:
        d=pe.get_data(rva & 0xfffff, 32)
        print(hex(rva), d[:32])
    except Exception as e:
        print(hex(rva), e)

# What about RBX=0x0049509800000000 - high part 0x495098?
print('RBX high', hex(0x495098))
# UTF16 'IP' = 0x0049 0x0050?
