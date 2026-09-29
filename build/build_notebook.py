#!/usr/bin/env python3
"""
Build the networking tutorial notebooks.

    python build/build_notebook.py [--out-dir DIR]

Produces
  networking_fundamentals.ipynb          learner version (stubs, outputs cleared)
  networking_fundamentals_solved.ipynb   every stub replaced by its solution (unexecuted;
                                         verify_notebooks.py executes it and saves outputs)
and prints per-part statistics (questions / coding exercises).
"""
import argparse
import os
import sys

import nbformat

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from nb import Builder  # noqa: E402
import part00, part01, part02, part03, part04, part05  # noqa: E402
import part06, part07, part08, part09, part10  # noqa: E402

PARTS = [part00, part01, part02, part03, part04, part05, part06, part07, part08, part09, part10]


def build():
    B = Builder()
    for p in PARTS:
        p.build(B)
    return B


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out-dir", default=os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    args = ap.parse_args()
    B = build()
    learner, solved = B.notebooks()
    for nb in (learner, solved):
        nbformat.validate(nb)
    lp = os.path.join(args.out_dir, "networking_fundamentals.ipynb")
    sp = os.path.join(args.out_dir, "networking_fundamentals_solved.ipynb")
    nbformat.write(learner, lp)
    nbformat.write(solved, sp)
    print(f"wrote {lp} ({len(learner.cells)} cells)")
    print(f"wrote {sp}")
    tq = tc = 0
    print(f"\n{'Part':<5} {'Title':<42} {'Questions':>9} {'Coding':>7}")
    for key, st in B.stats.items():
        print(f"{key:<5} {st['title']:<42} {st['questions']:>9} {st['coding']:>7}")
        tq += st["questions"]
        tc += st["coding"]
    print(f"{'':<5} {'TOTAL':<42} {tq:>9} {tc:>7}   coding share = {tc / max(1, tq + tc):.0%}")


if __name__ == "__main__":
    main()
