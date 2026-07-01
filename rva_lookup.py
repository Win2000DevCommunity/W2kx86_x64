"""Reverse / forward RVA-map lookup helper for debugging the translator.

The translator dumps ``x86_rva translated_off`` pairs (hex) via DUMP_RVA_MAP.
This tool answers the two questions that come up constantly while tracing:

  * forward:  given an x86 RVA, where did it land in the PE64 blob?
  * reverse:  given a translated offset (e.g. a ``main+0x....`` call site from
              the api log), which x86 RVA produced it?

Usage:
    python rva_lookup.py <rva.txt> r 0x31FB9 0x125E2      # reverse (translated -> x86)
    python rva_lookup.py <rva.txt> f 0x6581 0xA4E7        # forward  (x86 -> translated)

For reverse lookups it prints the closest mapped translated offset at or below
the query plus the few surrounding pairs so you can see slot collapse / drift.
"""
from __future__ import annotations

import bisect
import sys


def load(path):
    fwd = {}
    for line in open(path):
        line = line.strip()
        if not line:
            continue
        a, b = line.split()
        fwd[int(a, 16)] = int(b, 16)
    # reverse: sorted list of (translated_off, x86_rva)
    rev = sorted((v, k) for k, v in fwd.items())
    rev_offs = [t for t, _ in rev]
    return fwd, rev, rev_offs


def reverse(rev, rev_offs, q):
    i = bisect.bisect_right(rev_offs, q) - 1
    print(f"  query translated 0x{q:X}:")
    for j in range(max(0, i - 2), min(len(rev), i + 3)):
        t, x = rev[j]
        mark = "  <==" if j == i else ""
        print(f"    translated 0x{t:<8X}  <-  x86 0x{x:X}{mark}")


def forward(fwd, q):
    if q in fwd:
        print(f"  x86 0x{q:X}  ->  translated 0x{fwd[q]:X}")
    else:
        # nearest below
        keys = sorted(fwd)
        i = bisect.bisect_right(keys, q) - 1
        for j in range(max(0, i - 1), min(len(keys), i + 2)):
            k = keys[j]
            print(f"    x86 0x{k:<6X}  ->  translated 0x{fwd[k]:X}"
                  + ("  <== nearest below (exact miss)" if k <= q else ""))


def main():
    path = sys.argv[1]
    mode = sys.argv[2]
    fwd, rev, rev_offs = load(path)
    for s in sys.argv[3:]:
        q = int(s, 16)
        if mode == "r":
            reverse(rev, rev_offs, q)
        else:
            forward(fwd, q)


if __name__ == "__main__":
    main()
