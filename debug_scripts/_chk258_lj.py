import pefile, struct
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

# univ258 pure - longjmp at waiter, shim contents
pe = pefile.PE("build_univ258/cmd_pure.exe")
md = Cs(CS_ARCH_X86, CS_MODE_64)
print("=== 258 waiter ===")
for i in md.disasm(pe.get_data(0x45820, 0x40), 0x80045820):
    print(f"  {i.address-0x80000000:06X}: {i.mnemonic} {i.op_str}")

shim = pefile.PE("build_univ258/w2kshim64.dll")
for exp in shim.DIRECTORY_ENTRY_EXPORT.symbols:
    if exp.name == b"longjmp":
        blob = shim.get_data(exp.address, 0x55)
        print("258 longjmp movsxd", b"\x48\x63\xc2" in blob)
        print("258 longjmp mov eax,edx", b"\x89\xd0" in blob)
        for i in md.disasm(blob, 0):
            if i.address > 0x40:
                print(f"  {i.address:04X}: {i.mnemonic} {i.op_str}")

# What does IAT 84e78 point to at load - check import
for e in pe.DIRECTORY_ENTRY_IMPORT:
    for imp in e.imports:
        if imp.name and b"longjmp" in imp.name:
            print("import", e.dll, imp.name, hex(imp.address - 0x80000000 if imp.address else 0))
