import os, subprocess, pathlib
root = pathlib.Path(r"c:\Users\win2000\Desktop\Nouveau dossier\Nouveau dossier (9)\X86_X64")
src = pathlib.Path(r"C:\Users\win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU\cmd.exe")
out = root / "build_univ138"
out.mkdir(exist_ok=True)
env = os.environ.copy(); env["PURE"]="1"; env["DUMP_RVA_MAP"]=str(out/"rva.txt"); env["PYTHONUNBUFFERED"]="1"
cmd=[r"C:\Python314\python.exe","-u",str(root/"x86_x64.py"),"--pure","--win10-test-shim",str(src),str(out/"cmd_pure.exe")]
log=open(out/"build.log","w",encoding="utf-8",errors="replace"); err=open(out/"build.err","w",encoding="utf-8",errors="replace")
p=subprocess.Popen(cmd,cwd=str(root),env=env,stdout=log,stderr=err)
(out/"build.pid").write_text(str(p.pid)); print("started", p.pid)
