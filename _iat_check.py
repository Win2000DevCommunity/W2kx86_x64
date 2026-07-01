#!/usr/bin/env python3
import ctypes as C, struct, os, dbg_fault as df
df.suppress_fault_ui()
exe = os.path.abspath(r'..\win2000_x64\cmd_shim.exe')
si = df.STARTUPINFO(); pi = df.PROCESS_INFORMATION()
df.k32.CreateProcessW(None, f'"{exe}" /c echo test', None, None, False, 0x4, None, None,
                      C.byref(si), C.byref(pi))
base = 0x80000000
for rva in [0x6D3F8, 0x6D438, 0x6D420, 0x6D690]:
    buf = C.create_string_buffer(8)
    df.k32.ReadProcessMemory(pi.hProcess, C.c_void_p(base + rva), buf, 8, C.byref(C.c_size_t()))
    val = struct.unpack('<Q', buf.raw)[0]
    print(f'0x{rva:X} -> 0x{val:X}  {df.PeImportMap(exe).name_for_slot(rva)}')
df.k32.TerminateProcess(pi.hProcess, 0)
