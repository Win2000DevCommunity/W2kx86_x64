import struct, pathlib, subprocess, os
# IAT name for 85570
pe=pathlib.Path("build_univ230/cmd_both.exe").read_bytes()
# parse imports roughly from dbg or pe file
# read slot
e=struct.unpack_from("<I",pe,0x3C)[0]
ib=struct.unpack_from("<Q",pe,e+24+24)[0]
# find .idata / iat
ns=struct.unpack_from("<H",pe,e+6)[0]; so=struct.unpack_from("<H",pe,e+20)[0]; sec=e+24+so
for i in range(ns):
    o=sec+i*40
    name=pe[o:o+8].split(b"\0")[0]
    vs,va,rs,rp=struct.unpack_from("<IIII",pe,o+8)
    print(name, hex(va), hex(rs))

# smoke 3 times
os.chdir("build_univ230")
for i in range(3):
    r=subprocess.run(["cmd_both.exe","/c","echo","w2ktest"],capture_output=True,timeout=12)
    print(i, hex(r.returncode&0xffffffff), b"w2ktest" in r.stdout, r.stdout[-40:])
