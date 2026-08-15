import pathlib, struct, subprocess

raw = pathlib.Path("build_univ34/cmd_pure.exe").read_bytes()
# verify no unrebased 0x4ad20c00 as store imm near the site
if struct.pack("<I", 0x4AD20C00) in raw:
    print("WARN: old VA still in binary")
else:
    print("OK: old VA 0x4ad20c00 absent")
# expect rebased
exp = 0x80061C00
print("rebased present", struct.pack("<I", exp & 0xFFFFFFFF) in raw)

exe = str(pathlib.Path("build_univ34/cmd_pure.exe").resolve())
p = subprocess.run(
    [exe, "/c", "echo", "w2ktest"],
    stdin=subprocess.DEVNULL,
    capture_output=True,
    timeout=15,
)
print("rc", p.returncode, hex(p.returncode & 0xFFFFFFFF))
print("stdout", repr(p.stdout))
print("stderr", repr(p.stderr[:300]))
