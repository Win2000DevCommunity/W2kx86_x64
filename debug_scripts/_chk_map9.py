from pathlib import Path
from tools.audit_calls import load_map
rmap=load_map(Path("build_univ9/rva.txt"))
print("0x195d2", hex(rmap.get(0x195d2,0)))
print("near", [(hex(o),hex(n)) for o,n in sorted(rmap.items()) if abs(n-0x2fda4)<20 and 0x195c0<=o<=0x195f0])
