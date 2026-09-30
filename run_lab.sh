#!/usr/bin/env bash
# Launch the networking lab in JupyterLab using the "netlab" conda env (xeus-cling C++17).
# Usage: ./run_lab.sh [notebook.ipynb]   (default: networking_fundamentals.ipynb)
set -euo pipefail

ENV_NAME="netlab"
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NOTEBOOK="${1:-networking_fundamentals.ipynb}"

# Locate the env prefix without relying on shell activation.
if command -v mamba >/dev/null 2>&1; then
    CONDA_BIN=mamba
elif command -v conda >/dev/null 2>&1; then
    CONDA_BIN=conda
else
    CONDA_BIN=""
    for c in "$HOME/miniforge3/bin/mamba" "$HOME/miniforge3/bin/conda"; do
        [ -x "$c" ] && CONDA_BIN="$c" && break
    done
fi
[ -n "$CONDA_BIN" ] || { echo "error: mamba/conda not found" >&2; exit 1; }

PREFIX="$("$CONDA_BIN" env list 2>/dev/null | awk -v n="$ENV_NAME" '$1==n {print $NF}')"
if [ -z "$PREFIX" ] || [ ! -x "$PREFIX/bin/jupyter" ]; then
    echo "error: env '$ENV_NAME' missing. Create it with:" >&2
    echo "  mamba create -n $ENV_NAME -c conda-forge xeus-cling jupyterlab nbformat nbconvert" >&2
    exit 1
fi

# Cling finds the C++ stdlib via the env's compiler, so the env's bin must be first on PATH.
export PATH="$PREFIX/bin:$PATH"
# Ignore user-site packages (e.g. the broken ~/.local jupyter) so only the env is used.
export PYTHONNOUSERSITE=1

command -v x86_64-conda-linux-gnu-c++ >/dev/null 2>&1 \
    || { echo "error: env compiler not found on PATH" >&2; exit 1; }
jupyter kernelspec list 2>/dev/null | grep -q xcpp17 \
    || { echo "error: xcpp17 kernel not registered in '$ENV_NAME'" >&2; exit 1; }
[ -f "$DIR/$NOTEBOOK" ] || [ -f "$NOTEBOOK" ] || { echo "error: notebook '$NOTEBOOK' not found" >&2; exit 1; }

cd "$DIR"
# Safe defaults: bind to localhost only, token auth stays on (Jupyter default).
exec jupyter lab --ip=127.0.0.1 "$NOTEBOOK"
