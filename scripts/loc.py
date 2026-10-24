#!/usr/bin/env python3
"""Line counts for the README: library/binary source excluding the trailing
`#[cfg(test)]` unit-test module of each file, plus test/bench/example code."""
import glob
import os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def count(pattern):
    return sum(len(open(f).read().splitlines()) for f in glob.glob(os.path.join(ROOT, pattern), recursive=True))


src = unit = 0
for f in sorted(glob.glob(os.path.join(ROOT, "src/**/*.rs"), recursive=True)):
    lines = open(f).read().splitlines()
    cut = next((i for i, l in enumerate(lines) if l.strip() == "#[cfg(test)]"), len(lines))
    src += cut
    unit += len(lines) - cut
print(f"src (non-test, incl. docs/blank): {src}")
print(f"unit tests inside src:            {unit}")
print(f"tests/ benches/ examples/:        {count('tests/**/*.rs') + count('benches/**/*.rs') + count('examples/**/*.rs')}")
