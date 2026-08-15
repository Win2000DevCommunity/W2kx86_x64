import pefile, subprocess, sys

pe = pefile.PE(r'C:\Users\win2000\Desktop\Nouveau dossier\cmd_xp.exe')
machine = 'x64' if pe.FILE_HEADER.Machine == 0x8664 else ('x86' if pe.FILE_HEADER.Machine == 0x14C else '?')
print(f"Machine: 0x{pe.FILE_HEADER.Machine:04X} ({machine})")
print(f"ImageBase: 0x{pe.OPTIONAL_HEADER.ImageBase:X}")
print(f"Entry: 0x{pe.OPTIONAL_HEADER.AddressOfEntryPoint:X}")
print(f"Sections:")
for s in pe.sections:
    print(f"  {s.Name.decode().rstrip(chr(0)):8s} RVA=0x{s.VirtualAddress:05X} size=0x{s.Misc_VirtualSize:05X}")
print()

print("Looking for _controlfp in imports:")
for entry in pe.DIRECTORY_ENTRY_IMPORT:
    for imp in entry.imports:
        if imp.name and b'control' in imp.name.lower():
            print(f"  {entry.dll.decode()}!{imp.name.decode()}")

print()
print("Testing if binary runs:")
try:
    result = subprocess.run([r'C:\Users\win2000\Desktop\Nouveau dossier\cmd_xp.exe', '/c', 'echo', 'hello'], 
                          capture_output=True, timeout=5, text=True)
    print(f"  exit={result.returncode}")
    print(f"  stdout: {result.stdout.strip()}")
    print(f"  stderr: {result.stderr.strip()}")
except Exception as e:
    print(f"  Failed: {e}")
