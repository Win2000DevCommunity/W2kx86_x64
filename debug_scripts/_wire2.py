from pathlib import Path
p=Path('x86x64/translator/_image.py')
t=p.read_text(encoding='utf-8')
if 'formatmessage_call_rbx' in t:
    print('already')
else:
    old=(
        '                if n_fmh:\n'
        '                    print(f"        Final pure FormatMessage arg-home fixes: {n_fmh}")\n'
        '                n_cur = self._pure_seed_stream_cursor_from_parse_buffer(blob)'
    )
    new=(
        '                if n_fmh:\n'
        '                    print(f"        Final pure FormatMessage arg-home fixes: {n_fmh}")\n'
        '                n_fmr = self._pure_fix_formatmessage_call_rbx(blob)\n'
        '                if n_fmr:\n'
        '                    print(f"        Final pure FormatMessage call-rbx reloads: {n_fmr}")\n'
        '                n_cur = self._pure_seed_stream_cursor_from_parse_buffer(blob)'
    )
    if old not in t:
        print('not found, try alt')
        idx=t.find('FormatMessage arg-home')
        print(repr(t[idx:idx+250]))
    else:
        p.write_text(t.replace(old,new,1),encoding='utf-8')
        print('wired call-rbx')