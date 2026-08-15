"""Quick patch: fix ADD rsp for _chkstk functions to match V2 frame sizes."""
import sys
path = sys.argv[1] if len(sys.argv) > 1 else 'build_out125/cmd_pure.exe'

with open(path, 'rb+') as f:
    # ADD at file 0x1274E: was 0x2458, change to match _chkstk size 0x2470
    # Actually, the ADD should equal the _chkstk allocation. 
    # _chkstk(0x2470) with alignment: 0x2470 % 16 = 0, no extra alignment.
    # So ADD = 0x2470
    f.seek(0x1274E)
    old = int.from_bytes(f.read(4), 'little')
    print(f'ADD at 0x1274E: {old:#x} -> 0x2470')
    f.seek(0x1274E)
    f.write((0x2470).to_bytes(4, 'little'))
    
    f.seek(0x43196)
    old2 = int.from_bytes(f.read(4), 'little')
    print(f'ADD at 0x43196: {old2:#x} -> 0x2470')
    f.seek(0x43196)
    f.write((0x2470).to_bytes(4, 'little'))

print('Done')
