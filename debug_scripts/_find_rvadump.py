# Quick: can we import translator and get rva_map for just these RVAs via translate?
# Too slow maybe - try loading existing if any
import os
cands=[]
for root,dirs,files in os.walk('.'):
  if 'agent' in root or '__pycache__' in root: continue
  for f in files:
    if 'rva' in f.lower() and f.endswith(('.txt','.map','.csv','.json')):
      cands.append(os.path.join(root,f))
print('\n'.join(cands[:40]))
