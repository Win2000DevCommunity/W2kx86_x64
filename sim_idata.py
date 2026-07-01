import importlib
mod = importlib.import_module('x86_x64')
path = r'C:\Users\Win2000\Downloads\(ROLL-UP1)Windows2000-KB891861-v2-x86-ENU\cmd.exe'
with open(path, 'rb') as f:
    pe = mod.PE32Image(f.read())
imports = mod.transform_imports(pe.parse_imports())
desc_bytes = (len(imports) + 1) * 20
cursor = (desc_bytes + 7) & ~7
idata_rva = 0x8e000
for imp in imports:
    nfuncs = len(imp['functions'])
    cursor = (cursor + 7) & ~7
    ilt_off = cursor
    cursor += (nfuncs + 1) * 8
    iat_off = cursor
    cursor += (nfuncs + 1) * 8
    cursor += len(imp['dll'].encode('ascii') + b'\x00')
    for fn in imp['functions']:
        if fn['name']:
            cursor += 2 + len(fn['name'].encode('ascii')) + 1
    print(imp['dll'], hex(idata_rva + iat_off), iat_off % 8)
