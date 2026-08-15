import subprocess, os, tempfile, pathlib
exe = pathlib.Path("build_univ53/cmd_heal6.exe").resolve()
# Attach to a real console via STARTF
si = subprocess.STARTUPINFO()
p = subprocess.Popen([str(exe), "/c", "echo", "w2ktest"],
    stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
out, err = p.communicate(input=b"\n", timeout=5)
print("rc", hex(p.returncode & 0xffffffff) if p.returncode else 0)
print("out", out)
print("err", err[:200] if err else b"")