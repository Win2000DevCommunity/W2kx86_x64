"""Analyze _selfcall_dbg.txt against rva.txt: categorize 843 neutralized sites."""
import bisect
import collections
import sys

BUILD = sys.argv[1] if len(sys.argv) > 1 else 'build_univ361'

# Load rva map (x86_rva -> x64_rva)
fwd = {}
rev = {}
for line in open(f'{BUILD}/rva.txt', errors='replace'):
    pp = line.replace(',', ' ').split()
    if len(pp) >= 2:
        try:
            x, t = int(pp[0], 16), int(pp[1], 16)
        except ValueError:
            continue
        fwd[x] = t
        rev[t] = x
keys = sorted(rev)

def x86_for(off):
    i = bisect.bisect_right(keys, off) - 1
    if i < 0:
        return None
    k = keys[i]
    return rev[k], k, off - k

cats = collections.Counter()
by_anchor = collections.defaultdict(list)
resolve_fail_tgts = collections.Counter()
no_tgt_anchors = collections.Counter()

for line in open('_selfcall_dbg.txt', errors='replace'):
    line = line.strip()
    if not line:
        continue
    if line.startswith('stub='):
        parts = dict()
        for tok in line.split():
            if '=' in tok and not tok.startswith('nearest='):
                k, _, v = tok.partition('=')
                parts[k] = v
        off = int(parts.get('stub', '0'), 16)
        r = x86_for(off)
        if r:
            xr, ka, d = r
            by_anchor[xr].append(off)
        else:
            by_anchor[-1].append(off)
        cats['neutralized'] += 1
    elif line.startswith('REPATCH-NO-TGT'):
        parts = dict()
        for tok in line.split():
            if '=' in tok and not tok.startswith('anchors='):
                k, _, v = tok.partition('=')
                parts[k] = v
        off = int(parts.get('stub', '0'), 16)
        r = x86_for(off)
        if r:
            no_tgt_anchors[r[0]] += 1
        cats['no_tgt'] += 1
    elif line.startswith('REPATCH-RESOLVE-FAIL'):
        parts = dict()
        for tok in line.split():
            if '=' in tok:
                k, _, v = tok.partition('=')
                parts[k] = v
        tgt = int(parts.get('tgt_x86', '0'), 16)
        resolve_fail_tgts[tgt] += 1
        cats['resolve_fail'] += 1

print('categories:', dict(cats))
print()
print('top 25 neutralized-site x86 anchors (caller functions):')
for xr, offs in sorted(by_anchor.items(), key=lambda kv: -len(kv[1]))[:25]:
    print(f'  x86 0x{xr:X}: {len(offs)} sites')
print()
print('REPATCH-NO-TGT by anchor:')
for xr, n in no_tgt_anchors.most_common(20):
    print(f'  x86 0x{xr:X}: {n}')
print()
print('REPATCH-RESOLVE-FAIL target distribution (x86 target RVAs):')
for tgt, n in resolve_fail_tgts.most_common(25):
    print(f'  tgt x86 0x{tgt:X}: {n}')
