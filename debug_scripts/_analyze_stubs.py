import struct

with open('build_univ355/cmd_pure.exe', 'rb') as f:
    data = f.read()

pro = bytes.fromhex('41554989e54883ec204883e4f0')
epi = bytes.fromhex('4c89ec415d')
mov_eax = bytes.fromhex('B800000100')
PRO_LEN = 13
EPI_LEN = 5

# Find all neutralized self-call stubs
positions = []
p = 0
while p < len(data) - PRO_LEN - 5 - EPI_LEN:
    if data[p:p + PRO_LEN] != pro:
        p += 1
        continue
    j = p + PRO_LEN
    epi_pos = j + 5
    if epi_pos + EPI_LEN > len(data):
        p += 1
        continue
    if data[epi_pos:epi_pos + EPI_LEN] != epi:
        p += 1
        continue
    if data[j:j+5] == mov_eax:
        positions.append(p)
    p += 1

print(f'Total neutralized stubs: {len(positions)}')

# Analyze the distribution and neighbors
# Are they adjacent to each other?
adjacent = 0
for i in range(1, len(positions)):
    if positions[i] - positions[i-1] == 23:
        adjacent += 1
print(f'Adjacent pairs (23 bytes apart): {adjacent}')

# What's around the stubs? Check if they're inside larger wrappers
# A stub followed by another prologue means nested wrappers
print('\nFirst 10 stub positions:')
for pos in positions[:10]:
    print(f'  0x{pos:X}')

# Check for clusters
print('\nClusters (gaps > 64 bytes separate clusters):')
clusters = []
cur_start = positions[0]
prev = positions[0]
for pos in positions[1:]:
    if pos - prev > 64:
        clusters.append((cur_start, prev, (prev - cur_start) // 23 + 1))
        cur_start = pos
    prev = pos
clusters.append((cur_start, prev, (prev - cur_start) // 23 + 1))
print(f'{len(clusters)} clusters, top 10 by size:')
clusters.sort(key=lambda c: -c[2])
for start, end, cnt in clusters[:10]:
    print(f'  0x{start:X}-0x{end:X}: {cnt} stubs')

# What does the code look like just before a stub?
print('\nContext before first 3 stubs (30 bytes):')
for pos in positions[:3]:
    before = data[max(0,pos-30):pos]
    print(f'  0x{pos:X}: {before.hex()}')
