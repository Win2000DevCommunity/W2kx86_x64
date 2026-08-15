import struct
import pefile

# Load original x86 cmd.exe
pe86 = pefile.PE(r'C:\Users\win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU\cmd.exe')

# Find .text section
for sec in pe86.sections:
    name = sec.Name.rstrip(b'\x00').decode()
    if name == '.text':
        text_va = sec.VirtualAddress
        text_raw = sec.PointerToRawData
        text_data = sec.get_data()
        print(f'.text VA=0x{text_va:X} Raw=0x{text_raw:X} Size=0x{len(text_data):X}')
        break

# We need to find the x86 code that translates to the x64 code at main+0x4D114-0x4D140
# The x64 code pattern:
# 48 B9 ... movabs rcx, <pointer>
# 48 C7 C2 02 00 00 00  mov rdx, 2  (or BA 02 00 00 00)
# 49 B8 ... movabs r8, <pointer>
# 44 8B 4D F8  mov r9d, [rbp-8]
# 48 B8 ... movabs rax, <iat_slot>
# 48 8B 00  mov rax, [rax]
# FF D0  call rax

# In the x86 original, this would be:
# push [ebp-8]
# push <pointer2>   (or mov eax, ptr; push eax)
# push 2
# push <pointer1>
# call ds:[iat_slot]

# Let's search the x86 .text for the FF 15 pattern (call ds:[...])
# that corresponds to _except_handler3

# First, find _except_handler3's IAT slot RVA
for entry in pe86.DIRECTORY_ENTRY_IMPORT:
    if entry.dll and b'MSVCRT' in entry.dll.upper():
        for imp in entry.imports:
            if imp.name and b'_except_handler3' in imp.name:
                iat_rva_86 = imp.address
                print(f'_except_handler3 x86 IAT slot: RVA=0x{iat_rva_86:X}')
                break

# Now search for FF 15 <iat_rva> in the x86 text
print(f'\nSearching for calls to IAT slot 0x{iat_rva_86:X}...')
target_bytes = struct.pack('<I', iat_rva_86)
pattern = b'\xFF\x15' + target_bytes

count = 0
pos = 0
while True:
    idx = text_data.find(pattern, pos)
    if idx < 0:
        break
    rva = text_va + idx
    print(f'  Found at RVA 0x{rva:X}: {text_data[idx:idx+6].hex()}')
    # Show surrounding x86 code
    start = max(0, idx - 30)
    end = min(len(text_data), idx + 10)
    context = text_data[start:end]
    print(f'    Context: {context.hex()}')
    count += 1
    pos = idx + 1
    if count >= 5:
        print('  ... (more results)')
        break

print(f'Total: {count}+ occurrences')
