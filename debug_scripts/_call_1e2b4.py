import pefile, struct
pe = pefile.PE("build_univ258/cmd_probe_jcc.exe")
text = pe.sections[0].get_data()
base = pe.sections[0].VirtualAddress
target = 0x1E2B4
hits=[]
for i in range(len(text)-5):
    if text[i]==0xE8:
        rel=struct.unpack_from('<i', text, i+1)[0]
        if (i+5+rel) == target - base:
            hits.append(base+i)
print('calls to 1E2B4', [hex(h) for h in hits])
# also 1E2B4+something if homes skipped
for tgt in [0x1E2B4, 0x1E2C8, 0x1E2D4, 0x1E2D8]:
  hits=[]
  for i in range(len(text)-5):
    if text[i]==0xE8:
      rel=struct.unpack_from('<i', text, i+1)[0]
      if (i+5+rel) == tgt - base:
        hits.append(base+i)
  print(hex(tgt), [hex(h) for h in hits[:20]])
