# Quick live test: ecx+exitw with soft gate on exit code 1 when sticky==0
import struct, pathlib, subprocess, sys, shutil
from x86x64.translator._healing import HealingMixin

class T(HealingMixin):
    pass

pe = bytearray(pathlib.Path("build_univ257/cmd_pure.exe").read_bytes())
e = struct.unpack_from("<I", pe, 0x3C)[0]
ns = struct.unpack_from("<H", pe, e + 6)[0]; so = struct.unpack_from("<H", pe, e + 20)[0]; sec = e + 24 + so
for i in range(ns):
    o = sec + i * 40
    if pe[o:o + 5] == b".text":
        vs, va, rs, rp = struct.unpack_from("<IIII", pe, o + 8); break
blob = bytearray(pe[rp:rp + rs])
t = T(); t._cmd_no_hacks = True; t._pure_cave_cursor = 0; t.new_base = 0x80000000
print("ecx", t._pure_fix_missing_push_ecx_local_before_csr(blob))
# Custom exit stub: if sticky==0 and ecx==1: ret; else TerminateProcess
nb=0x80000000; sticky=nb+0x5BE00; iat=nb+0x845E0
dead = bytes.fromhex("48894c240848895424104c894424184c894c242048c7c100000000c3")
# need longer stub - use cave
at = blob.find(dead)
print("dead at", hex(at+va))
# Check trailing rets
print("trail", blob[at+len(dead):at+len(dead)+8].hex())

stub = bytearray()
# cmp ecx,1; jne do_exit
stub += b"\x83\xf9\x01"
stub += b"\x75\x14"  # jne +20
# movabs r11, sticky; cmp dword [r11],0; jne do_exit; ret
stub += b"\x49\xbb" + struct.pack("<Q", sticky)
stub += b"\x41\x83\x3b\x00"
stub += b"\x75\x01"  # jne +1
stub += b"\xc3"      # ret (suppress)
# do_exit:
stub += b"\x89\xca"  # mov edx,ecx
stub += b"\x48\xc7\xc1\xff\xff\xff\xff"
stub += b"\x48\xb8" + struct.pack("<Q", iat)
stub += b"\x48\x8b\x00\xff\xe0"
print("stub len", len(stub), "dead len", len(dead))
# too long for in-place - use jmp to cave
cave = len(blob)
blob.extend(b"\x00"*64)
blob[cave:cave+len(stub)] = stub
# replace dead with jmp cave; nops; need keep size
jmp = b"\xe9" + struct.pack("<i", cave - (at+5)) + b"\x90"*(len(dead)-5)
blob[at:at+len(dead)] = jmp

# also set SingleCommand when? for now just soft exit
# Apply rjoin already in pure

pe[rp:rp+rs] = blob[:rs]  # may truncate cave!
# need to extend section - for probe, append to file after .text carefully
# Simpler: put cave in existing padding
blob = bytearray(pe[rp:rp + rs])  # reset
t = T(); t._cmd_no_hacks = True; t._pure_cave_cursor = 0; t.new_base = 0x80000000
t._pure_fix_missing_push_ecx_local_before_csr(blob)
at = blob.find(dead)
# find padding cave
cave = t._pure_find_padding_cave(blob, len(stub)+8)
print("cave", hex(cave+va) if cave>=0 else None, "need", len(stub))
if cave < 0:
    # search 0x90 sled
    for i in range(len(blob)-80):
        if blob[i:i+40] == b"\x90"*40:
            cave=i; break
    print("nop sled", hex(cave+va) if cave else None)
