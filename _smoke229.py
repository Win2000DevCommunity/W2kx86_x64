import sys, subprocess, pathlib
sys.path.insert(0,'.')
import dbg_fault as df
df.suppress_fault_ui()
exe = pathlib.Path('build_univ229/cmd_pure.exe').resolve()
try:
    r = subprocess.run([str(exe), '/c', 'echo', 'w2ktest'], capture_output=True,
                       timeout=25, cwd=str(exe.parent),
                       creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
    print('exit', hex(r.returncode & 0xffffffff))
    print('stdout', r.stdout[:400])
    print('w2ktest', b'w2ktest' in r.stdout)
except subprocess.TimeoutExpired as e:
    print('HANG', (e.stdout or b'')[:200])
