"""Smoke tests for native vs --win10-test-shim cmd builds."""
import struct
import os
import subprocess
import sys
import tempfile
import shutil
import ctypes
from ctypes import wintypes

OUT = r"C:\Users\Win2000\Desktop\Nouveau dossier\Nouveau dossier (9)\win2000_x64"
SRC = r"C:\Users\Win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU\cmd.exe"
SCRIPT = r"C:\Users\Win2000\Desktop\Nouveau dossier\Nouveau dossier (9)\X86_X64\x86_x64.py"
NT = r"C:\Users\Win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU\ntdll.dll"
SYS32 = r"C:\Windows\System32"

k32 = ctypes.WinDLL("kernel32", use_last_error=True)


def suppress_fault_ui() -> None:
    """Prevent Visual Studio / WER JIT debugger popup on child crash."""
    k32.SetErrorMode(0x0002 | 0x0001 | 0x8000)


def build(name: str, shim: bool) -> str:
    dst = os.path.join(OUT, name)
    args = [sys.executable, SCRIPT, SRC, dst, "--ntdll-ref", NT, "--static-only"]
    if shim:
        args.append("--win10-test-shim")
    print(f"BUILD {name} shim={shim}")
    r = subprocess.run(args, capture_output=True, text=True, timeout=300)
    if r.returncode != 0:
        print(" BUILD FAIL", r.stderr[-400:])
        return ""
    for line in r.stdout.splitlines():
        if any(k in line for k in ("Function-driven", "Import shim", "w2kshim", "Output:")):
            print(" ", line.strip())
    return dst


def pe_info(path: str):
    b = open(path, "rb").read()
    pe = struct.unpack_from("<I", b, 0x3C)[0]
    entry = struct.unpack_from("<I", b, pe + 24 + 16)[0]
    opt_sz = struct.unpack_from("<H", b, pe + 20)[0]
    n = struct.unpack_from("<H", b, pe + 6)[0]
    sec_off = pe + 24 + opt_sz
    text_raw = 0
    for i in range(n):
        o = sec_off + i * 40
        if b[o : o + 5] == b".text":
            text_raw = struct.unpack_from("<I", b, o + 16)[0]
    return len(b), entry, text_raw


def rva_to_off(data, rva):
    pe = struct.unpack_from("<I", data, 0x3C)[0]
    opt_sz = struct.unpack_from("<H", data, pe + 20)[0]
    n = struct.unpack_from("<H", data, pe + 6)[0]
    sec_off = pe + 24 + opt_sz
    for i in range(n):
        o = sec_off + i * 40
        vs, va, rawsz, rawptr = struct.unpack_from("<IIII", data, o + 8)
        if va <= rva < va + max(vs, rawsz):
            return rawptr + (rva - va)
    return None


def import_dlls(path: str):
    data = open(path, "rb").read()
    pe = struct.unpack_from("<I", data, 0x3C)[0]
    opt_off = pe + 24
    imp_rva, _ = struct.unpack_from("<II", data, opt_off + 120)
    dlls = []
    off = rva_to_off(data, imp_rva)
    while off is not None:
        ilt = struct.unpack_from("<I", data, off)[0]
        name_rva = struct.unpack_from("<I", data, off + 12)[0]
        if ilt == 0 and name_rva == 0:
            break
        no = rva_to_off(data, name_rva)
        dll = b""
        p = no
        while data[p] != 0:
            dll += bytes([data[p]])
            p += 1
        dlls.append(dll.decode())
        off += 20
    return dlls


def missing_imports(path: str, search_dir: str):
    data = open(path, "rb").read()
    pe = struct.unpack_from("<I", data, 0x3C)[0]
    opt_off = pe + 24
    imp_rva, _ = struct.unpack_from("<II", data, opt_off + 120)
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    LoadLibraryW = k32.LoadLibraryW
    LoadLibraryW.restype = wintypes.HMODULE
    GetProcAddress = k32.GetProcAddress
    GetProcAddress.restype = ctypes.c_void_p
    GetProcAddress.argtypes = [wintypes.HMODULE, wintypes.LPCSTR]
    cache = {}
    missing = []
    off = rva_to_off(data, imp_rva)
    while off is not None:
        ilt = struct.unpack_from("<I", data, off)[0]
        name_rva = struct.unpack_from("<I", data, off + 12)[0]
        if ilt == 0 and name_rva == 0:
            break
        no = rva_to_off(data, name_rva)
        dll = b""
        p = no
        while data[p] != 0:
            dll += bytes([data[p]])
            p += 1
        dll = dll.decode()
        key = dll.lower()
        if key not in cache:
            local = os.path.join(search_dir, dll)
            cache[key] = LoadLibraryW(local if os.path.isfile(local) else os.path.join(SYS32, dll))
        h = cache[key]
        ilt_off = rva_to_off(data, ilt)
        idx = 0
        while True:
            thunk = struct.unpack_from("<Q", data, ilt_off + idx * 8)[0]
            if thunk == 0:
                break
            if thunk & (1 << 63):
                sym = "#" + str(thunk & 0xFFFF)
                proc = GetProcAddress(h, ctypes.c_void_p(thunk & 0xFFFF)) if h else None
            else:
                hint_off = rva_to_off(data, thunk & 0xFFFFFFFF)
                nm = b""
                q = hint_off + 2
                while data[q] != 0:
                    nm += bytes([data[q]])
                    q += 1
                sym = nm.decode()
                proc = GetProcAddress(h, sym.encode()) if h else None
            if not proc:
                missing.append((dll, sym))
            idx += 1
        off += 20
    return missing


def run_cmd(label: str, exe_path: str, cwd: str | None = None, copy_files=None):
    suppress_fault_ui()
    td = tempfile.mkdtemp(prefix="w2ktest_")
    iso = os.path.join(td, "cmd64.exe")
    shutil.copy2(exe_path, iso)
    if copy_files:
        for src, name in copy_files:
            if os.path.isfile(src):
                shutil.copy2(src, os.path.join(td, name))
    work = cwd or td
    r = subprocess.run(
        [iso if cwd else iso, "/c", f"echo {label}_OK"],
        capture_output=True,
        text=True,
        timeout=20,
        cwd=work,
    )
    ec = r.returncode & 0xFFFFFFFF
    print(f"  {label:30s} exit=0x{ec:08X}  out={r.stdout.strip()!r}")
    return ec


def main():
    os.makedirs(OUT, exist_ok=True)
    native = build("cmd_native.exe", False)
    shim = build("cmd_shim.exe", True)
    shim_dll = os.path.join(OUT, "w2kshim64.dll")

    print("\n=== PE SUMMARY ===")
    for label, p in [("native", native), ("shim", shim)]:
        if not p or not os.path.isfile(p):
            continue
        sz, entry, text_raw = pe_info(p)
        dlls = import_dlls(p)
        print(f"{label}: size={sz} entry=0x{entry:X} text_raw=0x{text_raw:X}")
        print(f"  imports: {dlls}")

    print("\n=== MISSING IMPORTS vs Win10 System32 ===")
    for label, p in [("native", native), ("shim", shim)]:
        if not p:
            continue
        miss = missing_imports(p, SYS32)
        print(f"{label}: {len(miss)} missing")
        for row in miss:
            print(f"  {row[0]}!{row[1]}")

    print("\n=== RUN TESTS ===")
    r = subprocess.run([SRC, "/c", "echo X86_OK"], capture_output=True, text=True, timeout=15)
    print(f"  {'x86 Win2000 cmd':30s} exit=0x{r.returncode & 0xFFFFFFFF:08X}  out={r.stdout.strip()!r}")

    if native:
        run_cmd("native isolated", native)
    if shim:
        run_cmd("shim isolated", shim, copy_files=[(shim_dll, "w2kshim64.dll")])
    folder_cmd = os.path.join(OUT, "cmd.exe")
    if os.path.isfile(folder_cmd):
        run_cmd("win2000_x64 folder", folder_cmd, cwd=OUT)

    # Load translated DLLs from tree
    print("\n=== TRANSLATED DLL LOAD (win2000_x64) ===")
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    LoadLibraryW = k32.LoadLibraryW
    LoadLibraryW.restype = wintypes.HMODULE
    for name in ["ntdll.dll", "kernel32.dll", "msvcrt.dll"]:
        p = os.path.join(OUT, name)
        if not os.path.isfile(p):
            print(f"  {name}: missing")
            continue
        h = LoadLibraryW(p)
        print(f"  {name}: {'OK' if h else 'FAIL err='+str(ctypes.get_last_error())}")


if __name__ == "__main__":
    main()
