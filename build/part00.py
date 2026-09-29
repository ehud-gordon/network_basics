from nb import dedent, hexdump_py

SETUP = r'''
// ============================ SETUP CELL ==================================
// Run this cell once, first. It contains every #include used anywhere in the
// notebook plus the test helpers (CHECK, CHECK_EQ, CHECK_NEAR) and hexdump().
#include <iostream>
#include <iomanip>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>
#include <array>
#include <map>
#include <unordered_map>
#include <sstream>
#include <bitset>
#include <optional>
#include <algorithm>
#include <thread>
#include <chrono>
#include <set>
#include <cmath>
#include <type_traits>
#include <csignal>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/time.h>
#include <cerrno>

#ifndef MSG_NOSIGNAL          // Linux has it; macOS does not (SIGPIPE is ignored below anyway)
#define MSG_NOSIGNAL 0
#endif

namespace nbtest {

// Writing to a TCP connection the peer has closed raises SIGPIPE, which would kill the kernel.
// Ignore it process-wide: send() then simply fails with errno EPIPE.
const bool sigpipe_ignored = (std::signal(SIGPIPE, SIG_IGN) != SIG_ERR);

int g_pass = 0;   // number of CHECKs that passed so far
int g_fail = 0;   // number of CHECKs that failed so far

// ---- turning a value into readable text (used when a CHECK_EQ fails) ----
template <typename T, typename = void>
struct is_streamable : std::false_type {};
template <typename T>
struct is_streamable<T, std::void_t<decltype(std::declval<std::ostream&>() << std::declval<const T&>())>>
    : std::true_type {};

template <typename T>
std::string show(const T& v) {
    std::ostringstream os;
    if constexpr (std::is_same_v<T, bool>) {
        os << (v ? "true" : "false");
    } else if constexpr (std::is_enum_v<T>) {
        os << "enum value " << static_cast<long long>(v);
    } else if constexpr (std::is_integral_v<T>) {
        // print integers in decimal AND hex: byte-order bugs jump out in hex
        os << +v << " (0x" << std::hex << +v << std::dec << ")";
    } else if constexpr (std::is_convertible_v<T, std::string>) {
        os << '"' << std::string(v) << '"';
    } else if constexpr (is_streamable<T>::value) {
        os << v;
    } else {
        os << "<value>";
    }
    return os.str();
}

template <typename U>
std::string show(const std::vector<U>& v) {
    std::ostringstream os;
    os << "{";
    for (size_t i = 0; i < v.size(); ++i) {
        if (i) os << ", ";
        if constexpr (std::is_same_v<U, uint8_t>)
            os << "0x" << std::hex << std::setw(2) << std::setfill('0') << unsigned(v[i]) << std::dec;
        else
            os << show(v[i]);
    }
    os << "}";
    return os.str();
}

// ---- the checks themselves: they print, count, and NEVER abort ----
bool check_impl(bool ok, const char* expr) {
    if (ok) { ++g_pass; std::cout << "✅ " << expr << "\n"; }
    else    { ++g_fail; std::cout << "❌ " << expr << "\n"; }
    return ok;
}

template <typename A, typename B>
bool check_eq_impl(const A& a, const B& b, const char* expr) {
    bool ok = (a == b);
    check_impl(ok, expr);
    if (!ok) std::cout << "     got:      " << show(a) << "\n     expected: " << show(b) << "\n";
    return ok;
}

bool check_near_impl(double a, double b, const char* expr) {
    // relative tolerance 1e-6 (plus a tiny absolute tolerance for values near 0)
    bool ok = std::fabs(a - b) <= 1e-6 * std::max(std::fabs(a), std::fabs(b)) + 1e-15;
    check_impl(ok, expr);
    if (!ok) std::cout << "     got:      " << a << "\n     expected: " << b << "\n";
    return ok;
}

void print_score() {
    std::cout << "Score so far: " << g_pass << " passed, " << g_fail << " failed"
              << " (re-running a test cell counts its CHECKs again)\n";
}

void reset_score() { g_pass = 0; g_fail = 0; }

// ---- hexdump: 16 bytes per line: offset | hex bytes | printable ASCII ----
void hexdump(const uint8_t* p, size_t n) {
    for (size_t off = 0; off < n; off += 16) {
        std::cout << std::hex << std::setfill('0') << std::setw(4) << off << "  ";
        for (size_t i = 0; i < 16; ++i) {
            if (off + i < n) std::cout << std::setw(2) << unsigned(p[off + i]) << ' ';
            else             std::cout << "   ";
            if (i == 7) std::cout << ' ';
        }
        std::cout << " |";
        for (size_t i = 0; i < 16 && off + i < n; ++i) {
            uint8_t c = p[off + i];
            std::cout << ((c >= 32 && c < 127) ? char(c) : '.');
        }
        std::cout << "|\n";
    }
    std::cout << std::dec << std::setfill(' ');
}

void hexdump(const std::vector<uint8_t>& v) { hexdump(v.data(), v.size()); }

} // namespace nbtest

using namespace nbtest;

#define CHECK(expr)          nbtest::check_impl(static_cast<bool>(expr), #expr)
#define CHECK_EQ(a, b)       nbtest::check_eq_impl((a), (b), #a " == " #b)
#define CHECK_NEAR(a, b)     nbtest::check_near_impl((a), (b), #a " ≈ " #b)
'''


def build(B):
    B.part("0", "Using this notebook")
    B.md(r"""
    # Networking Fundamentals — an active-learning lab in C++

    This notebook teaches networking from first principles: TCP/IP, the OSI 7-layer model, and the
    devices in between (NIC, modem, switch, router, access point, the home "router" box).
    You will learn by **doing**: short explanations, brief questions, and C++ exercises that
    operate on **real bytes** laid out exactly as they travel on a real network.

    | Part | Topic | Time |
    |---|---|---|
    | 0 | Using this notebook | 10 min |
    | 1 | Bytes and bits primer | 35 min |
    | 2 | What a network is | 30 min |
    | 3 | Layering | 25 min |
    | 4 | Physical layer and hardware | 30 min |
    | 5 | Link layer: Ethernet | 35 min |
    | 6 | Network layer: IPv4 | 45 min |
    | 7 | Home and ISP infrastructure services | 35 min |
    | 8 | Transport layer: UDP and TCP | 45 min |
    | 9 | Sockets in practice (loopback only) | 35 min |
    | 10 | Capstone: dissect a real frame | 30 min |

    Total: about 6 hours.
    """)
    B.md(r"""
    # Part 0 — Using this notebook

    ## 0.1 How this notebook works

    A notebook is a list of **cells**. *Markdown* cells hold text; *code* cells hold C++ that the
    **kernel** (the program running your code, here *xeus-cling*, a C++ interpreter) executes
    when you press **Shift+Enter**. Cells run in the order *you* run them, and everything defined
    in one cell stays visible to later cells.

    Every concept follows the same rhythm:

    ```
    explanation (≤ ~150 words, diagram if useful)
        └─► 1–2 short questions ──► collapsed solution after each
        └─► coding exercise ──► test cell ──► collapsed solution
    ```

    * **Questions** are tagged *Why?*, *Predict the output*, *Compute*, or *Code reading*.
      Answer in your head or on paper **before** expanding the solution.
    * **Exercises** give you a *stub*: a function that compiles but returns a placeholder
      (`return 0;`, `return {};`). Replace the body, run the cell, then run the test cell below it.
    * **Solutions** are collapsed. Click **▶ Solution** to expand one.

    Tests mostly show ❌ until you solve the exercise. A few "rejects bad input" checks may already
    show ✅ on the untouched stub, because a stub that rejects everything happens to reject bad input too.
    """)
    B.question("concept", "You run the notebook top to bottom without solving anything. "
               "Should you expect errors, ❌ marks, or both?",
               r"""
               Only ❌ marks. Every stub compiles and returns a placeholder value, so every cell runs;
               the tests simply report that the placeholder is wrong. A *cell error* (red traceback)
               always means something else went wrong, typically the redefinition problem covered in §0.3.
               """)

    B.md(r"""
    ## 0.2 The setup cell

    The next cell must run **first**. It contains:

    * every `#include` used anywhere in the notebook;
    * `CHECK(expr)` prints ✅ or ❌ followed by the expression's text, and counts passes and failures;
    * `CHECK_EQ(a, b)` does the same for `a == b`, and on failure prints both values ("got" and "expected");
    * `CHECK_NEAR(a, b)` compares two floating-point numbers with a small relative tolerance;
    * `hexdump(p, n)` prints raw bytes (see §0.4);
    * `print_score()` and `reset_score()`.

    None of these helpers ever aborts the kernel: a failed check prints and moves on.
    """)
    B.code(SETUP, tags=["setup"])
    B.md(r"""
    Here is what checks look like. One of them fails **on purpose**: read how the failure is reported.
    """)
    B.code(r"""
    {
        int answer = 6 * 7;
        CHECK(answer > 40);
        CHECK_EQ(answer, 42);
        CHECK_EQ(answer, 43);          // fails on purpose: note "got" vs "expected"
        CHECK_NEAR(0.1 + 0.2, 0.3);    // exact == would fail for doubles; NEAR tolerates rounding
    }
    """)
    B.code(r"""
    print_score();
    reset_score();   // start from zero for the real exercises
    """)

    B.md(r"""
    ## 0.3 xeus-cling quirks (read this once, it will save you time)

    xeus-cling interprets C++ cell by cell, which changes a few rules:

    1. **No `main()`.** Statements at the top level of a cell run immediately.
    2. **A cell either *defines* or *runs*, never both.** A cell that starts with `namespace`,
       `struct`, or a function definition may contain only definitions. A cell that starts with a
       statement (`CHECK(...)`, `std::cout << ...`, `{`) may contain only statements. This is why
       every exercise has a *definition* cell followed by a separate *test* cell.
    3. **Redefinition errors.** Defining the same function or struct twice is an error, and re-running
       a definition cell does exactly that. To limit the damage, each exercise lives in its own
       namespace, such as `namespace ex5_3 { ... }`.

    > **If you get a redefinition error, restart the kernel and use *Run → Run All Above* (JupyterLab)
    > or *Run Above* (VS Code) from the cell you are editing, then run your cell again.**

    Test cells are wrapped in `{ ... }`: their local variables vanish at the closing brace, so test
    cells *can* be re-run freely.
    """)
    B.question("why", r"""You fix a bug inside `namespace ex1_6 { ... }` and re-run the cell. Cling reports
    `redefinition of 'read_be16'`. Why, and what do you do?""",
               r"""
               The first run already defined `ex1_6::read_be16` in the interpreter's memory, and C++ forbids
               two definitions of one function (the *One Definition Rule*). Cling cannot "replace" a definition
               the way Python rebinds a name. **Fix:** restart the kernel, then *Run All Above* and run your
               edited cell. Your edited source is kept, because only the interpreter's memory is reset.

               *Misconception:* renaming the namespace to `ex1_6b` "fixes" it, but then the test cell, which calls
               `ex1_6::read_be16`, still sees the old, buggy version.
               """)

    demo = b"Hello, network!\n"
    B.md(r"""
    ## 0.4 Looking at raw bytes with `hexdump`

    A **byte** is 8 bits and holds a value from 0 to 255. Networking code constantly inspects raw
    bytes, and decimal is a poor fit: a byte is written far more compactly in **hexadecimal**
    (base 16, digits `0–9` then `a–f` for 10–15). One byte is always exactly two hex digits,
    `00` to `ff`, and C++ writes a hex literal with the prefix `0x` (e.g. `0x41` = 4·16 + 1 = 65).
    Part 1 practises this properly.

    `hexdump` prints 16 bytes per line:

    ```
    @DEMO@
    ^^^^  ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^  ^^^^^^^^^^^^^^^^^^
    offset   16 bytes in hex (extra gap after the 8th)         printable chars
    ```

    The *offset* (in hex) is the position of the line's first byte. Text is stored as bytes using
    **ASCII**, a table mapping characters to numbers (`'H'` = 0x48, `'e'` = 0x65, newline = 0x0a).
    Non-printable bytes appear as `.` on the right.
    """.replace("@DEMO@", hexdump_py(demo)))
    B.code(r"""
    {
        const char* msg = "Hello, network!\n";
        hexdump(reinterpret_cast<const uint8_t*>(msg), std::strlen(msg));
    }
    """)
    B.question("predict", r"""The string `"Hi!"` is dumped with `hexdump`. `'H'` is 0x48, `'i'` is 0x69,
    and `'!'` is 0x21. What does the single output line look like?""",
               """
               ```
               @HI@
               ```
               Three bytes, offset `0000`, the hex bytes in memory order, then blank padding up to 16 columns,
               and the printable characters between the bars. The dump shows bytes in the order they sit
               in memory. That order matters a lot in Part 1: for multi-byte numbers it is **not** always the order you
               would write the digits.
               """.replace("@HI@", hexdump_py(b"Hi!")))
    B.recap(
        ["Run the **setup cell** first; every later cell depends on it.",
         "`CHECK`, `CHECK_EQ`, and `CHECK_NEAR` print ✅/❌, count results, and never abort.",
         "A cell either defines things or runs statements; exercises live in unique namespaces.",
         "Redefinition error → restart the kernel → *Run All Above*.",
         "`hexdump` shows bytes as offset, hex, and ASCII columns."],
        ["why re-running a definition cell fails in cling, and how to recover;",
         "what each of the three columns of a hexdump line means;",
         "why a byte is written as exactly two hex digits."])
