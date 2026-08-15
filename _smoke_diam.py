"""BP at 28858 (lstrlen concat size) and 19dc4 (alloc) during /c echo."""
import struct, pathlib, sys, os
sys.path.insert(0, ".")
import dbg_fault as df

exe = pathlib.Path("build_univ229/cmd_diam.exe")
# Need shim in cwd
os.chdir("build_univ229")

# Find text VA base
pe = exe.read_bytes() if exe.is_absolute() else pathlib.Path("cmd_diam.exe").read_bytes()
e = struct.unpack_from("<I", pe, 0x3C)[0]
ib = struct.unpack_from("<Q", pe, e+24+24)[0]
# RVAs
targets = {
    "28858_lensum": ib + 0x28858,
    "288ee_alloc": ib + 0x288ee,  # call alloc inside 28858
    "c546_alloc20a": ib + 0xc546,
    "c597_d08c": ib + 0xc597,
    "189c4_echo": ib + 0x189c4,
    "19dc4_alloc": ib + 0x19dc4,
}

# Use dbg_fault's debugger if it has BP helpers
print("ib", hex(ib))
print("targets", {k: hex(v) for k,v in targets.items()})

# Quick smoke first
import subprocess
r = subprocess.run(
    ["cmd_diam.exe", "/c", "echo", "w2ktest"],
    capture_output=True, timeout=8, cwd=".")
print("exit", hex(r.returncode & 0xffffffff))
print("out", r.stdout[:200])
print("err", r.stderr[:200])
