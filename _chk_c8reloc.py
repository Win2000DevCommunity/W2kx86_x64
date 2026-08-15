import struct, pefile
pe=pefile.PE("build_univ212/cmd_pure.exe")
# check relocs targeting 0x588d8
target=0x588d8
hits=[]
for b in pe.DIRECTORY_ENTRY_BASERELOC:
    for e in b.entries:
        if e.rva == target or abs(e.rva - target) < 4:
            hits.append((e.rva, e.type))
print("reloc hits near c8d8", hits[:20], "count", len(hits))
# read initial memory by simulating - just file value
data=open("build_univ212/cmd_pure.exe","rb").read()
for s in pe.sections:
    if s.Name.startswith(b".data"):
        off=s.PointerToRawData+0x8d8
        print("file c8d8", hex(struct.unpack_from("<Q", data, off)[0]))
        print("nearby", data[off-8:off+16].hex())
