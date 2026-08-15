"""PE/COFF constants used by the reader and writer."""

from __future__ import annotations

DOS_SIGNATURE = b'MZ'
PE_SIGNATURE = b'PE\x00\x00'
PE_OFFSET_FIELD = 0x3C

# -- machine types --------------------------------------------------------
IMAGE_FILE_MACHINE_I386 = 0x014C
IMAGE_FILE_MACHINE_AMD64 = 0x8664

# -- optional header magics ----------------------------------------------
PE32_MAGIC = 0x010B
PE32PLUS_MAGIC = 0x020B

#: Optional header sizes: standard fields, then the 16 data directories.
PE64_OPT_STANDARD = 112
PE64_OPT_TOTAL = 240
NUM_DATA_DIRECTORIES = 16
SECTION_HEADER_SIZE = 40
COFF_HEADER_SIZE = 20

# -- file characteristics -------------------------------------------------
IMAGE_FILE_EXECUTABLE_IMAGE = 0x0002
IMAGE_FILE_LARGE_ADDRESS_AWARE = 0x0020
IMAGE_FILE_DLL = 0x2000

# -- section characteristics ---------------------------------------------
IMAGE_SCN_CNT_CODE = 0x0000_0020
IMAGE_SCN_CNT_INITIALIZED_DATA = 0x0000_0040
IMAGE_SCN_CNT_UNINITIALIZED_DATA = 0x0000_0080
IMAGE_SCN_MEM_DISCARDABLE = 0x0200_0000
IMAGE_SCN_MEM_EXECUTE = 0x2000_0000
IMAGE_SCN_MEM_READ = 0x4000_0000
IMAGE_SCN_MEM_WRITE = 0x8000_0000

# -- subsystems -----------------------------------------------------------
IMAGE_SUBSYSTEM_NATIVE = 1
IMAGE_SUBSYSTEM_WINDOWS_GUI = 2
IMAGE_SUBSYSTEM_WINDOWS_CUI = 3

# -- DLL characteristics --------------------------------------------------
IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE = 0x0040
IMAGE_DLLCHARACTERISTICS_NX_COMPAT = 0x0100
IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE = 0x8000

# -- data directory indices ----------------------------------------------
DIR_EXPORT = 0
DIR_IMPORT = 1
DIR_RESOURCE = 2
DIR_EXCEPTION = 3
DIR_SECURITY = 4
DIR_BASERELOC = 5
DIR_DEBUG = 6
DIR_TLS = 9
DIR_LOAD_CONFIG = 10
DIR_IAT = 12

# -- base relocation types -----------------------------------------------
IMAGE_REL_BASED_ABSOLUTE = 0
IMAGE_REL_BASED_HIGHLOW = 3
IMAGE_REL_BASED_DIR64 = 10

# -- default layout -------------------------------------------------------
DEFAULT_SECTION_ALIGNMENT = 0x1000
DEFAULT_FILE_ALIGNMENT = 0x200

#: Preferred base for translated EXEs.
#:
#: Two constraints meet here. Below 4 GiB, so that image pointers stored in the
#: 32-bit slots a Win2000 binary still uses keep a zero high dword and a 32-bit
#: load zero-extends to the right pointer. Above 2 GiB, so every image VA
#: exceeds INT32_MAX and the emitters never take a rel32 fast path that would
#: mix a build-time offset with an absolute address.
PE64_EXE_BASE = 0x8000_0000
#: Preferred base for translated DLLs.
PE64_DLL_BASE = 0x1_8000_0000

#: Stock MS-DOS stub: prints a message and exits.
#:
#: The dword at 0x3C is ``e_lfanew`` and must point at the PE signature, which
#: for this 128-byte stub means 0x80.
DOS_STUB = bytes.fromhex(
    '4d5a90000300000004000000ffff0000'
    'b8000000000000004000000000000000'
    '00000000000000000000000000000000'
    '000000000000000000000000'  '80000000'
    '0e1fba0e00b409cd21b8014ccd215468'
    '69732070726f6772616d2063616e6e6f'
    '742062652072756e20696e20444f5320'
    '6d6f64652e0d0d0a2400000000000000'
)
assert len(DOS_STUB) == 0x80, 'DOS stub must be 0x80 bytes'
assert int.from_bytes(DOS_STUB[0x3C:0x40], 'little') == 0x80, \
    'DOS stub e_lfanew must point at 0x80'
