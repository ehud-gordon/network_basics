#!/usr/bin/env bash
# Build both notebooks, execute them with the xcpp17 kernel via nbconvert, and check the results.
#
#   conda activate netlab          # or: mamba activate netlab   (the kernel needs the env's compiler on PATH)
#   bash build/build_and_verify.sh
#
# Result (in the repository root):
#   networking_fundamentals.ipynb          learner version, outputs cleared
#   networking_fundamentals_solved.ipynb   solved version, executed, with outputs
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

python "$ROOT/build/build_notebook.py" --out-dir "$ROOT"

cp "$ROOT/networking_fundamentals.ipynb" "$WORK/learner.ipynb"
cp "$ROOT/networking_fundamentals_solved.ipynb" "$WORK/solved.ipynb"

for nb in solved learner; do
  echo
  echo "=== executing $nb notebook with nbconvert ==="
  jupyter nbconvert --to notebook --execute \
      --ExecutePreprocessor.kernel_name=xcpp17 --ExecutePreprocessor.timeout=60 \
      "$WORK/$nb.ipynb" --output "$WORK/$nb.executed.ipynb"
done

echo
echo "=== solved notebook: every CHECK must pass ==="
python "$ROOT/build/verify_notebooks.py" --no-execute --expect-all-pass "$WORK/solved.executed.ipynb"
echo
echo "=== learner notebook: no cell errors (failing CHECKs are expected) ==="
python "$ROOT/build/verify_notebooks.py" --no-execute "$WORK/learner.executed.ipynb"

# keep the executed solved copy as the reference solution
cp "$WORK/solved.executed.ipynb" "$ROOT/networking_fundamentals_solved.ipynb"
echo
echo "done: learner notebook (clean) and executed solved notebook written to $ROOT"
