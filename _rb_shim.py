# Rebuild shim DLL quickly and patch longjmp into existing probe
import pathlib, shutil, subprocess, sys, struct
# Prefer using shim builder module
from x86x64.shim.builder import build_w2kshim64
out = pathlib.Path("build_univ258/w2kshim64_new.dll")
# check signature
import inspect
print("build_w2kshim64", build_w2kshim64)
