# Networking Fundamentals — an active-learning lab in C++

`networking_fundamentals.ipynb` is a hands-on tutorial on networking fundamentals (bytes and
endianness, delays, OSI/TCP-IP layering, physical layer and hardware, Ethernet, IPv4/ARP/ICMP,
NAT/DHCP/DNS, UDP/TCP, sockets), ending in a capstone that dissects and builds a real
Ethernet + IPv4 + TCP frame. Every concept follows the same rhythm: a short explanation, brief
questions with collapsed solutions, and C++ exercises with test cells that operate on real
header bytes. Budget about 6 hours.

| Part | Topic | Questions | Coding exercises |
|---|---|---:|---:|
| 0 | Using this notebook | 3 | 0 |
| 1 | Bytes and bits primer | 9 | 7 |
| 2 | What a network is | 6 | 5 |
| 3 | Layering | 5 | 2 |
| 4 | Physical layer and hardware | 9 | 3 |
| 5 | Link layer: Ethernet | 5 | 5 |
| 6 | Network layer: IPv4 | 9 | 9 |
| 7 | Home and ISP infrastructure services | 5 | 5 |
| 8 | Transport layer: UDP and TCP | 10 | 7 |
| 9 | Sockets in practice (loopback only) | 5 | 6 |
| 10 | Capstone: dissect a real frame | 11 | 3 |
| | **Total** | **77** | **52** (40%) |

## Files

| file | what it is |
|---|---|
| `networking_fundamentals.ipynb` | the learner notebook: stubs to fill in, outputs cleared |
| `networking_fundamentals_solved.ipynb` | every stub replaced by its solution, executed, with outputs |
| `build/build_notebook.py` | generates both notebooks with `nbformat` (`build/part00.py` … `part10.py` hold the content) |
| `build/nb.py` | notebook builder + Python reference implementations that compute every expected value (checksums, header bytes, subnets, …) |
| `build/verify_notebooks.py` | executes/inspects a notebook and counts cell errors and ✅/❌ checks |
| `build/build_and_verify.sh` | rebuilds, executes both notebooks with `nbconvert`, and verifies them |

## Setup

The notebook uses the **xeus-cling** C++17 kernel (`xcpp17`). On Linux (on Windows, use WSL):

```bash
mamba create -n netlab -c conda-forge xeus-cling jupyterlab nbformat nbconvert
mamba activate netlab
jupyter lab networking_fundamentals.ipynb
```

On Apple-silicon Macs, conda-forge has no native `xeus-cling` build; create the environment from
the Intel build, which runs under Rosetta: `CONDA_SUBDIR=osx-64 mamba create -n netlab -c conda-forge ...`.

**Launch Jupyter from the activated environment.** Cling locates the C++ standard library by
running the environment's compiler (`x86_64-conda-linux-gnu-c++`). If that compiler is not on
`PATH`, every cell fails with `cannot extract standard library include paths`.

Work through the notebook top to bottom. If a cell reports a *redefinition* error (re-running a
definition cell), restart the kernel and use *Run All Above*.

## Rebuilding and verifying

```bash
mamba activate netlab
bash build/build_and_verify.sh
```

This regenerates both notebooks, executes each one with

```bash
jupyter nbconvert --to notebook --execute --ExecutePreprocessor.kernel_name=xcpp17 --ExecutePreprocessor.timeout=60 <file>
```

and checks that the solved notebook has no cell errors and every `CHECK` passes (apart from the single
intentional failure in the Part 0 demo), and that the learner notebook runs with no cell errors.
Only the executed solved copy is kept; the learner notebook stays output-free.

## xeus-cling notes

* A cell must either *define* things or *run* statements; cling rejects cells that mix them. Every
  exercise therefore has a definition cell followed by a separate `{ ... }` test cell.
* Each exercise lives in its own namespace (`ex5_3`, …); helpers from earlier exercises are re-provided
  in `// PROVIDED (you wrote this in §X.Y)` cells, so a learner who gets stuck is never blocked later.
* `std::thread` links without extra pragmas on the tested setup (xeus-cling 0.15.3, cling 0.9).
* The setup cell ignores `SIGPIPE`, so that a `send()` on a closed TCP connection cannot kill the kernel.
  All socket exercises use loopback only, bind to port 0, set `SO_RCVTIMEO`, and join their threads in the same cell.
