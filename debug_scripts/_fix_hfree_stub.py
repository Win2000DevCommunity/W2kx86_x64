from pathlib import Path
path = Path('x86x64/translator/_healing.py')
text = path.read_text(encoding='utf-8')
start = text.index('    def _pure_fix_heapfree_missing_win64_args(self, out: bytearray) -> int:')
end = text.index('    def _pure_fix_ff35_helper_calls(')
new = (
    '    def _pure_fix_heapfree_missing_win64_args(self, out: bytearray) -> int:\n'
    '        """Stub: HeapFree arg heal disabled until old-pointer source is known."""\n'
    '        return 0\n\n'
)
path.write_text(text[:start] + new + text[end:], encoding='utf-8')
import py_compile
py_compile.compile(str(path), doraise=True)
print('ok')
