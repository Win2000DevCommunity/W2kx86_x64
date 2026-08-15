# Check if rva_map dump exists for univ258
import os, glob
for p in sorted(glob.glob('build_univ258/*'))[:40]:
    print(p)
print('---')
for p in sorted(glob.glob('build_univ258/**/*map*', recursive=True))[:20]:
    print(p)
for p in sorted(glob.glob('**/*rva_map*', recursive=True))[:20]:
    print(p)
