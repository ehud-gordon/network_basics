"""
Notebook builder + Python reference implementations used to compute every
expected value (checksums, header bytes, subnet results, ...) that appears
in the notebook. Nothing numeric in the notebook is written by hand.
"""
from __future__ import annotations

import ipaddress
import re
import struct
import textwrap
from collections import OrderedDict

import nbformat as nbf

KERNELSPEC = {"name": "xcpp17", "display_name": "C++17", "language": "C++17"}


# --------------------------------------------------------------------------
# Small text helpers
# --------------------------------------------------------------------------
def dedent(s: str) -> str:
    return textwrap.dedent(s).strip("\n")


def dedent_q(s: str) -> str:
    """Dedent text whose first line starts right after the opening quotes."""
    lines = s.strip("\n").split("\n")
    if len(lines) == 1:
        return lines[0].strip()
    return lines[0].strip() + "\n" + textwrap.dedent("\n".join(lines[1:])).strip("\n")


def fill(src: str, **kw) -> str:
    """Replace @name@ placeholders (C++ never uses '@')."""
    for k, v in kw.items():
        token, v = f"@{k}@", str(v)
        out, pos = [], 0
        while True:
            i = src.find(token, pos)
            if i < 0:
                out.append(src[pos:])
                break
            line_start = src.rfind("\n", 0, i) + 1
            prefix = src[line_start:i]
            indent = prefix if prefix.strip() == "" else ""   # placeholder alone on its line?
            out.append(src[pos:i] + v.replace("\n", "\n" + indent))
            pos = i + len(token)
        src = "".join(out)
    if "@" in src and any(f"@{w}@" in src for w in kw):
        raise ValueError("unfilled placeholder")
    return src


def solution_md(explanation: str, code: str | None = None) -> str:
    """Exactly the collapsed-solution format required by the spec."""
    body = dedent(explanation)
    parts = ["<details>", "<summary><b>Solution</b> (click to expand)</summary>", "", body, ""]
    if code:
        parts += ["```cpp", dedent(code), "```", ""]
    parts.append("</details>")
    return "\n".join(parts)


# --------------------------------------------------------------------------
# Builder
# --------------------------------------------------------------------------
class Builder:
    def __init__(self):
        self.cells_learner: list = []
        self.cells_solved: list = []
        self.stats: "OrderedDict[str, dict]" = OrderedDict()
        self.cur_part = None
        self.qcount = 0
        self.snippets: dict[str, str] = {}   # reusable solution code by key

    # ---- structure -------------------------------------------------------
    def part(self, key: str, title: str):
        self.cur_part = key
        self.stats[key] = {"title": title, "questions": 0, "coding": 0}
        self.qcount = 0

    def _add(self, cell_l, cell_s=None):
        self.cells_learner.append(cell_l)
        self.cells_solved.append(cell_s if cell_s is not None else cell_l)

    def md(self, text: str, tags=None):
        c = nbf.v4.new_markdown_cell(dedent(text))
        if tags:
            c.metadata["tags"] = tags
        self._add(c)

    def code(self, src: str, tags=None):
        c = nbf.v4.new_code_cell(dedent(src))
        if tags:
            c.metadata["tags"] = tags
        self._add(c)

    # ---- question + collapsed solution -----------------------------------
    def question(self, qtype: str, text: str, solution: str, code: str | None = None):
        """qtype in {'why', 'predict', 'compute', 'code'} (label shown to learner)."""
        labels = {
            "why": "Why?",
            "predict": "Predict the output",
            "compute": "Compute",
            "code": "Code reading",
            "concept": "Concept",
        }
        self.qcount += 1
        num = f"Q{self.cur_part}.{self.qcount}"
        self.md(f"**{num}** *({labels[qtype]})* — {dedent_q(text)}", tags=["question"])
        self.md(solution_md(solution, code), tags=["solution"])
        self.stats[self.cur_part]["questions"] += 1

    # ---- coding exercise: prompt, stub, test, solution --------------------
    def exercise(self, ex_id: str, title: str, prompt: str, stub: str, solution: str,
                 test: str, explanation: str, snippet_key: str | None = None):
        self.md(f"### ✍️ Exercise {ex_id} — {title}\n\n{dedent(prompt)}", tags=["exercise-prompt"])
        stub_cell = nbf.v4.new_code_cell(dedent(stub))
        stub_cell.metadata["tags"] = ["exercise"]
        stub_cell.metadata["exercise_id"] = ex_id
        sol_cell = nbf.v4.new_code_cell(dedent(solution))
        sol_cell.metadata["tags"] = ["exercise", "solved"]
        sol_cell.metadata["exercise_id"] = ex_id
        self._add(stub_cell, sol_cell)
        self.md(f"**Test for Exercise {ex_id}** — run the next cell.", tags=["test-label"])
        self.code(test, tags=["test"])
        self.md(solution_md(explanation, solution), tags=["solution"])
        self.stats[self.cur_part]["coding"] += 1
        if snippet_key:
            self.snippets[snippet_key] = dedent(solution)

    # ---- PROVIDED cells: earlier solutions re-exposed in a fresh namespace ----
    def snippet_body(self, key: str) -> str:
        """Solution code of an earlier exercise without its `namespace exX_Y {` wrapper."""
        lines = self.snippets[key].split("\n")
        assert lines[0].startswith("namespace ") and lines[-1].strip() == "}", key
        return "\n".join(lines[1:-1]).strip("\n")

    def provided(self, ns: str, items: list, note: str = "", unqualify: bool = False):
        """items: list of (section, snippet_key) or (section, raw_code) with section like '1.6'."""
        out = []
        for sec, key in items:
            body = self.snippet_body(key) if key in self.snippets else dedent(key)
            if unqualify:   # everything lives in this one namespace: drop libX:: qualifiers
                body = re.sub(r"\blib\w*::", "", body)
            label = ("// GIVEN helper (new here, not an exercise)" if sec == "given"
                     else f"// PROVIDED (you wrote this in §{sec})")
            out.append(f"{label}\n{body}")
        src = f"namespace {ns} {{\n\n" + "\n\n".join(out) + f"\n\n}} // namespace {ns}"
        if note:
            self.md(note)
        self.code(src, tags=["provided"])

    # ---- recap -----------------------------------------------------------
    def recap(self, bullets: list[str], checklist: list[str]):
        lines = ["### 🔁 Recap", ""]
        lines += [f"- {dedent(b)}" for b in bullets]
        lines += ["", "**You should now be able to explain…**", ""]
        lines += [f"- [ ] {dedent(c)}" for c in checklist]
        self.md("\n".join(lines), tags=["recap"])

    # ---- output ------------------------------------------------------------
    def notebooks(self):
        out = []
        for cells in (self.cells_learner, self.cells_solved):
            nb = nbf.v4.new_notebook()
            nb.metadata["kernelspec"] = dict(KERNELSPEC)
            nb.metadata["language_info"] = {
                "name": "C++17",
                "codemirror_mode": "text/x-c++src",
                "file_extension": ".cpp",
                "mimetype": "text/x-c++src",
            }
            nb.cells = [nbf.from_dict(dict(c)) for c in cells]
            out.append(nb)
        return out


# --------------------------------------------------------------------------
# Python reference implementations (the "answer key")
# --------------------------------------------------------------------------
def be16(v: int) -> bytes:
    return struct.pack("!H", v)


def be32(v: int) -> bytes:
    return struct.pack("!I", v)


def inet_checksum(data: bytes) -> int:
    """RFC 1071 Internet checksum."""
    if len(data) % 2:
        data += b"\x00"
    s = 0
    for i in range(0, len(data), 2):
        s += (data[i] << 8) | data[i + 1]
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF


def ones_sum16(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    s = 0
    for i in range(0, len(data), 2):
        s += (data[i] << 8) | data[i + 1]
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return s


def ip2int(s: str) -> int:
    return int(ipaddress.IPv4Address(s))


def mac_bytes(s: str) -> bytes:
    return bytes(int(x, 16) for x in s.split(":"))


def eth_header(dst: str, src: str, ethertype: int) -> bytes:
    return mac_bytes(dst) + mac_bytes(src) + be16(ethertype)


def ipv4_header(src: str, dst: str, proto: int, payload_len: int, ttl=64, ident=0,
                df=True, tos=0, options: bytes = b"") -> bytes:
    ihl = 5 + len(options) // 4
    total = ihl * 4 + payload_len
    flags_frag = 0x4000 if df else 0
    hdr = struct.pack("!BBHHHBBH4s4s", (4 << 4) | ihl, tos, total, ident, flags_frag, ttl,
                      proto, 0, ipaddress.IPv4Address(src).packed,
                      ipaddress.IPv4Address(dst).packed) + options
    csum = inet_checksum(hdr)
    return hdr[:10] + be16(csum) + hdr[12:]


def pseudo_header(src: str, dst: str, proto: int, length: int) -> bytes:
    return (ipaddress.IPv4Address(src).packed + ipaddress.IPv4Address(dst).packed
            + bytes([0, proto]) + be16(length))


def udp_datagram(src: str, dst: str, sport: int, dport: int, payload: bytes) -> bytes:
    length = 8 + len(payload)
    hdr = struct.pack("!HHHH", sport, dport, length, 0)
    csum = inet_checksum(pseudo_header(src, dst, 17, length) + hdr + payload)
    if csum == 0:
        csum = 0xFFFF
    return struct.pack("!HHHH", sport, dport, length, csum) + payload


TCP_FLAG_NAMES = ["FIN", "SYN", "RST", "PSH", "ACK", "URG", "ECE", "CWR"]


def tcp_flags_str(f: int) -> str:
    # least-significant flag first (FIN, SYN, RST, PSH, ACK, ...), like Wireshark's "[SYN, ACK]"
    names = [TCP_FLAG_NAMES[i] for i in range(8) if f & (1 << i)]
    return "|".join(names) if names else "none"


def tcp_segment(src: str, dst: str, sport: int, dport: int, seq: int, ack: int, flags: int,
                window: int, options: bytes = b"", payload: bytes = b"", urg=0) -> bytes:
    assert len(options) % 4 == 0
    off = 5 + len(options) // 4
    hdr = struct.pack("!HHIIBBHHH", sport, dport, seq, ack, off << 4, flags, window, 0, urg) + options
    seglen = len(hdr) + len(payload)
    csum = inet_checksum(pseudo_header(src, dst, 6, seglen) + hdr + payload)
    return hdr[:16] + be16(csum) + hdr[18:] + payload


def cpp_bytes(b: bytes, per_line: int = 12, indent: str = "    ") -> str:
    """Format bytes as a C++ initializer list body."""
    lines = []
    for i in range(0, len(b), per_line):
        chunk = b[i:i + per_line]
        lines.append(indent + ", ".join(f"0x{x:02x}" for x in chunk) + ",")
    return "\n".join(lines)


def hexdump_py(b: bytes) -> str:
    """Same format as the C++ hexdump() in the setup cell."""
    out = []
    for off in range(0, len(b), 16):
        chunk = b[off:off + 16]
        hexpart = ""
        for i in range(16):
            hexpart += f"{chunk[i]:02x} " if i < len(chunk) else "   "
            if i == 7:
                hexpart += " "
        asc = "".join(chr(c) if 32 <= c < 127 else "." for c in chunk)
        out.append(f"{off:04x}  {hexpart} |{asc}|")
    return "\n".join(out)
