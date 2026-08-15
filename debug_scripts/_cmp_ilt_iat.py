#!/usr/bin/env python3
import struct, sys

data = open(sys.argv[1], 'rb').read()
ilt = 0x98FB8
iat = 0x99048
print('ILT vs IAT:')
for i in range(18):
    ilt_val = struct.unpack_from('<Q', data, ilt + i * 8)[0]
    iat_val = struct.unpack_from('<Q', data, iat + i * 8)[0]
    match = 'MATCH' if ilt_val == iat_val else 'MISMATCH'
    print(f'  [{i:2d}] ILT=0x{ilt_val:016X} IAT=0x{iat_val:016X} {match}')
