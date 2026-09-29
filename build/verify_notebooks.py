#!/usr/bin/env python3
"""
Execute (or just inspect) a notebook that uses the xcpp17 kernel and report:
  * cells that raised an error,
  * cells that wrote to stderr (compiler warnings/errors),
  * the number of ✅ and ❌ CHECK results.

    python build/verify_notebooks.py NOTEBOOK [--expect-all-pass] [--no-execute] [--save OUT]

Executing uses nbclient with allow_errors=True, which is what
`jupyter nbconvert --to notebook --execute --ExecutePreprocessor.kernel_name=xcpp17` does,
except that it keeps going after an error so that every problem is reported in one run.
With --no-execute the notebook's existing outputs are analysed (e.g. the output of nbconvert).

The Part 0 demo contains exactly one intentional failure (`answer == 43`); it is not counted
against --expect-all-pass.
"""
import argparse
import sys

import nbformat

INTENTIONAL = "❌ answer == 43"


def analyse(nb):
    errors, stderr_cells, fails = [], [], []
    n_pass = n_fail = 0
    for i, c in enumerate(nb.cells):
        if c.cell_type != "code":
            continue
        head = (c.source.splitlines() or [""])[0][:70]
        out = "".join(o.get("text", "") for o in c.outputs
                      if o.output_type == "stream" and o.get("name") == "stdout")
        err = "".join(o.get("text", "") for o in c.outputs
                      if o.output_type == "stream" and o.get("name") == "stderr")
        n_pass += out.count("✅")
        cell_fails = [ln for ln in out.splitlines() if ln.startswith("❌") and ln.strip() != INTENTIONAL]
        n_fail += len(cell_fails)
        if cell_fails:
            fails.append((i, head, out))
        if any(o.output_type == "error" for o in c.outputs):
            errors.append((i, head, err + "".join("\n".join(o.get("traceback", [])) for o in c.outputs
                                                   if o.output_type == "error")))
        elif err.strip():
            stderr_cells.append((i, head, err))
    return errors, stderr_cells, fails, n_pass, n_fail


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("notebook")
    ap.add_argument("--expect-all-pass", action="store_true")
    ap.add_argument("--no-execute", action="store_true")
    ap.add_argument("--save", default=None)
    ap.add_argument("--timeout", type=int, default=60)
    args = ap.parse_args()

    nb = nbformat.read(args.notebook, as_version=4)
    if not args.no_execute:
        from nbclient import NotebookClient
        NotebookClient(nb, timeout=args.timeout, kernel_name="xcpp17", allow_errors=True).execute()

    errors, stderr_cells, fails, n_pass, n_fail = analyse(nb)
    print(f"notebook: {args.notebook}")
    print(f"code cells: {sum(1 for c in nb.cells if c.cell_type == 'code')}")
    print(f"cell errors: {len(errors)}")
    for i, head, err in errors:
        print(f"  [cell {i}] {head}\n{err[:1500]}")
    print(f"cells with stderr output (no error): {len(stderr_cells)}")
    for i, head, err in stderr_cells:
        print(f"  [cell {i}] {head}\n{err[:800]}")
    print(f"CHECKs: {n_pass} ✅  {n_fail} ❌  (+1 intentional ❌ in the Part 0 demo)")
    if args.expect_all_pass:
        for i, head, out in fails:
            print(f"  [cell {i}] {head}\n{out[:1500]}")
    if args.save:
        nbformat.write(nb, args.save)
    ok = not errors and (not args.expect_all_pass or n_fail == 0)
    print("RESULT:", "OK" if ok else "FAILED")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
