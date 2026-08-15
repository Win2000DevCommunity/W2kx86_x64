from pathlib import Path
p = Path('x86x64/translator/_image.py')
t = p.read_text(encoding='utf-8')
needle = 'Final pure FormatMessage fallback fixes'
if 'FormatMessage arg-home' in t:
    print('already wired')
else:
    old = '''                if n_fm:
                    print(f\"        Final pure FormatMessage fallback fixes: {n_fm}\")
                n_cur = self._pure_seed_stream_cursor_from_parse_buffer(blob)'''
    # use actual quotes
    old = (
        '                if n_fm:\n'
        '                    print(f"        Final pure FormatMessage fallback fixes: {n_fm}")\n'
        '                n_cur = self._pure_seed_stream_cursor_from_parse_buffer(blob)'
    )
    new = (
        '                if n_fm:\n'
        '                    print(f"        Final pure FormatMessage fallback fixes: {n_fm}")\n'
        '                n_fmh = self._pure_fix_formatmessage_arg_homes(blob)\n'
        '                if n_fmh:\n'
        '                    print(f"        Final pure FormatMessage arg-home fixes: {n_fmh}")\n'
        '                n_cur = self._pure_seed_stream_cursor_from_parse_buffer(blob)'
    )
    if old not in t:
        print('OLD NOT FOUND')
    else:
        p.write_text(t.replace(old, new, 1), encoding='utf-8')
        print('wired ok')