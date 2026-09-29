from nb import fill


def build(B):
    B.part("1", "Bytes and bits primer")
    B.md(r"""
    # Part 1 — Bytes and bits primer

    Everything a network carries is a sequence of **bytes**. Before touching any protocol you need
    to be fluent at reading and building bytes: fixed-width integers, hex, bit masks, and byte order.
    """)

    # ------------------------------------------------------------------ 1.1
    B.md(r"""
    ## 1.1 Fixed-width integers

    A **bit** is 0 or 1; a **byte** is 8 bits. C++'s `int` has a platform-dependent size, which is
    useless for describing a protocol field "exactly 16 bits wide". The header `<cstdint>` provides
    exact widths:

    | type | bits | range |
    |---|---|---|
    | `uint8_t`  | 8  | 0 … 255 |
    | `uint16_t` | 16 | 0 … 65 535 |
    | `uint32_t` | 32 | 0 … 4 294 967 295 |
    | `uint64_t` | 64 | 0 … 2⁶⁴ − 1 |

    An $n$-bit unsigned type holds $0 \dots 2^n - 1$, and its arithmetic **wraps** modulo $2^n$
    (255 + 1 becomes 0 in a `uint8_t`).

    **Pitfall:** `uint8_t` is a character type, so `std::cout << b` prints a *character*.
    Write `+b` (unary plus promotes it to `int`) or `unsigned(b)` to print the number.
    """)
    x = (250 + 10) % 256
    B.question("predict", r"""`uint8_t x = 250; x += 10; std::cout << +x;` — what is printed?""",
               f"""
               **{x}**. 250 + 10 = 260, which does not fit in 8 bits; the stored value is
               260 mod 256 = {x}. Unsigned overflow is *well defined* in C++ (it wraps), whereas signed
               overflow is undefined behaviour. That is one reason protocol code uses unsigned types everywhere.
               """)
    B.question("predict", r"""`uint8_t b = 65; std::cout << b << " " << +b;` — what is printed?""",
               r"""
               **`A 65`**. `std::cout << b` treats a `uint8_t` as a `char`, and 65 is ASCII `'A'`. `+b`
               promotes it to `int` and prints the number. This bug is common when printing header bytes.
               """)
    B.exercise("1.1", "The largest value of an n-bit field",
               r"""
               Protocol fields often have odd widths (4, 13, or 20 bits). Write `max_value(bits)` returning
               $2^{bits} - 1$ for `bits` in 1…32, as a `uint32_t`.

               *Trap:* in C++, shifting a 32-bit value by 32 or more positions is **undefined behaviour**,
               so `(1u << 32) - 1` is not allowed. Handle `bits == 32` separately.
               """,
               r"""
               namespace ex1_1 {
               uint32_t max_value(int bits) {
                   // TODO: return 2^bits - 1 (careful with bits == 32)
                   return 0;
               }
               }
               """,
               r"""
               namespace ex1_1 {
               uint32_t max_value(int bits) {
                   if (bits >= 32) return 0xFFFFFFFFu;   // all 32 bits set; avoids the UB shift
                   return (1u << bits) - 1;              // e.g. bits=4: 0b10000 - 1 = 0b01111
               }
               }
               """,
               r"""
               {
                   CHECK_EQ(ex1_1::max_value(1), 1u);
                   CHECK_EQ(ex1_1::max_value(4), 15u);
                   CHECK_EQ(ex1_1::max_value(8), 255u);
                   CHECK_EQ(ex1_1::max_value(16), 65535u);
                   CHECK_EQ(ex1_1::max_value(32), 4294967295u);
               }
               """,
               r"""
               $2^n$ is `1u << n` (a 1 followed by $n$ zeros); subtracting 1 turns it into $n$ ones.
               For $n = 32$ the shift is undefined behaviour: on x86 the hardware masks the shift count to
               `32 & 31 = 0`, so it often *silently* yields `1 - 1 = 0`. The same trap appears when you build a
               `/0` subnet mask in Part 6.
               """)

    # ------------------------------------------------------------------ 1.2
    B.md(r"""
    ## 1.2 Hexadecimal and binary notation

    Hex (base 16) is the lingua franca of packet dumps because **one hex digit is exactly 4 bits**
    (a *nibble*), so a byte is two digits and the bit pattern can be read directly:

    ```
    hex digit:  0    1    2   ...  9    a    b    c    d    e    f
    bits:      0000 0001 0010 ... 1001 1010 1011 1100 1101 1110 1111

    0xC0A8  =  1100 0000 1010 1000  =  12·16³ + 0·16² + 10·16 + 8
    ```

    C++ literals: `0x2f` (hex), `0b0010'1111` (binary; `'` is an optional digit separator).
    To print hex: `std::cout << std::hex << std::setw(2) << std::setfill('0') << +b;`.
    `std::hex` and `setfill` are *sticky* (they stay in effect), so restore with `std::dec`;
    `setw` applies only to the next item.
    """)
    B.question("compute", r"""Convert `0xC0A8` to decimal, and `0b1010'0101` to hex.""",
               f"""
               * `0xC0A8` = 0xC0·256 + 0xA8 = 192·256 + 168 = **{0xC0A8}**.
               * `0b1010'0101`: split into nibbles, `1010` = a and `0101` = 5, giving **0x{0b10100101:02x}**.

               Splitting a byte into nibbles is the fastest way to convert between binary and hex; never go through decimal.
               """)
    B.exercise("1.2", "Format a byte as two hex digits",
               r"""
               Write `to_hex8(b)` returning exactly two **lowercase** hex digits, e.g. `0x0a` → `"0a"`.
               Use `std::ostringstream` (a stream that writes into a string, from `<sstream>`) with the
               manipulators above, and call `.str()` on it to get the result.
               """,
               r"""
               namespace ex1_2 {
               std::string to_hex8(uint8_t b) {
                   // TODO
                   return "";
               }
               }
               """,
               r"""
               namespace ex1_2 {
               std::string to_hex8(uint8_t b) {
                   std::ostringstream os;
                   // unsigned(b): print the number, not the character; setw(2)+setfill('0'): keep leading 0
                   os << std::hex << std::setw(2) << std::setfill('0') << unsigned(b);
                   return os.str();
               }
               }
               """,
               r"""
               {
                   CHECK_EQ(ex1_2::to_hex8(0x0a), "0a");
                   CHECK_EQ(ex1_2::to_hex8(0xff), "ff");
                   CHECK_EQ(ex1_2::to_hex8(0x00), "00");
                   CHECK_EQ(ex1_2::to_hex8(65), "41");
               }
               """,
               r"""
               Two classic bugs: forgetting `setw(2)`/`setfill('0')` (giving `"a"` instead of `"0a"`) and streaming
               the `uint8_t` directly (giving the *character* with code 0x41, i.e. `"A"`, instead of `"41"`).
               The stream is local, so its sticky `std::hex` does not leak into `std::cout`.
               """, snippet_key="to_hex8")

    # ------------------------------------------------------------------ 1.3
    B.md(r"""
    ## 1.3 Bitwise operators and masks

    Bits are numbered from **bit 0 = least significant** (value 1) up to bit 7 (value 128) in a byte.

    | op | meaning | example (8-bit) |
    |---|---|---|
    | `a & b` | AND: keep bits set in both | `1100'1010 & 0000'1111 = 0000'1010` |
    | `a \| b` | OR: set bits from either | `1100'0000 \| 0000'0011 = 1100'0011` |
    | `a ^ b` | XOR: bits that differ | `1111'0000 ^ 1010'1010 = 0101'1010` |
    | `~a` | NOT: flip every bit | `~0000'1111 = 1111'0000` |
    | `a << n`, `a >> n` | shift left/right by n | `0000'0001 << 3 = 0000'1000` |

    A **mask** is a constant selecting bits: `1u << i` selects bit *i*.
    Test: `(x >> i) & 1`. Set: `x | (1u << i)`. Clear: `x & ~(1u << i)`.

    **Pitfall (integer promotion):** C++ converts operands narrower than `int` to `int` before any
    operator, so `~uint8_t(0x0F)` is the `int` `0xFFFFFFF0`. Cast results back: `uint8_t(~x)`.
    """)
    B.question("predict", r"""`std::cout << std::hex << (0xF0 & 0x3C) << " " << (0xF0 | 0x0F) << " " << (0x5A ^ 0xFF);`""",
               f"""
               **`{0xF0 & 0x3C:x} {0xF0 | 0x0F:x} {0x5A ^ 0xFF:x}`**

               * `1111'0000 & 0011'1100 = 0011'0000` (only the overlap survives)
               * `1111'0000 | 0000'1111 = 1111'1111`
               * `0101'1010 ^ 1111'1111 = 1010'0101`: XOR with all ones flips every bit (like `~`, but without promotion surprises in 8 bits).
               """)
    B.exercise("1.3", "Get, set and clear one bit",
               r"""
               Implement the three helpers for bit index `i` in 0…7. Return `uint8_t` (cast!).
               """,
               r"""
               namespace ex1_3 {
               bool get_bit(uint8_t x, int i)      { return false; }  // TODO
               uint8_t set_bit(uint8_t x, int i)   { return 0; }      // TODO
               uint8_t clear_bit(uint8_t x, int i) { return 0; }      // TODO
               }
               """,
               r"""
               namespace ex1_3 {
               bool get_bit(uint8_t x, int i)      { return (x >> i) & 1u; }
               uint8_t set_bit(uint8_t x, int i)   { return uint8_t(x | (1u << i)); }
               uint8_t clear_bit(uint8_t x, int i) { return uint8_t(x & ~(1u << i)); }
               }
               """,
               r"""
               {
                   CHECK_EQ(ex1_3::get_bit(0b0000'0100, 2), true);
                   CHECK_EQ(ex1_3::get_bit(0b0000'0100, 3), false);
                   CHECK_EQ(ex1_3::get_bit(0x80, 7), true);
                   CHECK_EQ(ex1_3::set_bit(0x00, 7), 0x80);
                   CHECK_EQ(ex1_3::set_bit(0x01, 0), 0x01);     // setting a set bit changes nothing
                   CHECK_EQ(ex1_3::clear_bit(0xFF, 0), 0xFE);
                   CHECK_EQ(ex1_3::clear_bit(0x12, 4), 0x02);
               }
               """,
               r"""
               `~(1u << i)` is a mask with every bit set *except* bit *i*; AND-ing with it clears exactly that
               bit. Here the results always fit in 8 bits (the promoted `x` has zeros above bit 7, and the AND clears the
               rest), and converting to `uint8_t` is well defined (modulo 256). The `uint8_t(...)` casts document that intent
               and silence narrowing warnings. The real danger is a *bare* `~x`: for `uint8_t x = 0x0F`, `~x` is the `int`
               `0xFFFFFFF0`, whose upper 24 bits are all set, so comparing it with `0xF0` fails.
               """)

    # ------------------------------------------------------------------ 1.4
    B.md(r"""
    ## 1.4 Extracting a multi-bit field

    Protocol headers pack several small numbers into one byte. Example: a byte `0x45` holding two
    4-bit fields, *A* in the high nibble and *B* in the low nibble:

    ```
      bit:   7 6 5 4 | 3 2 1 0
    0x45 =   0 1 0 0 | 0 1 0 1
             A = 4   | B = 5
    ```

    General recipe for a field of `width` bits starting at bit `shift`:

    $$\text{field} = (b \gg \text{shift}) \;\&\; (2^{\text{width}} - 1)$$

    Shift the field down to bit 0, then mask off everything above it. Packing is the reverse:
    `(A << 4) | B`.
    """)
    fb = 0xB6
    B.question("compute", r"""For `b = 0xB6`, what is the 3-bit field starting at bit 2 (bits 2, 3, 4)?""",
               f"""
               `0xB6 = {fb:08b}`. Shift right by 2: `{fb >> 2:08b}`. Mask with `0b111`: `{(fb >> 2) & 7:03b}` = **{(fb >> 2) & 7}**.

               A common error is to mask first and then shift with the wrong mask (`b & 0b111` selects bits 0–2, not 2–4).
               If you mask first, the mask must be pre-shifted: `(b & (0b111 << 2)) >> 2`.
               """)
    B.exercise("1.4", "Get a field and pack two nibbles",
               r"""
               * `get_field(b, shift, width)`: the recipe above (width in 1…8).
               * `pack_nibbles(hi, lo)`: returns the byte with `hi` in bits 7–4 and `lo` in bits 3–0
                 (assume both are ≤ 15).
               """,
               r"""
               namespace ex1_4 {
               uint8_t get_field(uint8_t b, int shift, int width) { return 0; }  // TODO
               uint8_t pack_nibbles(uint8_t hi, uint8_t lo)       { return 0; }  // TODO
               }
               """,
               r"""
               namespace ex1_4 {
               uint8_t get_field(uint8_t b, int shift, int width) {
                   uint8_t mask = uint8_t((1u << width) - 1);   // width ones, e.g. width 3 -> 0b111
                   return uint8_t((b >> shift) & mask);
               }
               uint8_t pack_nibbles(uint8_t hi, uint8_t lo) {
                   return uint8_t((hi << 4) | (lo & 0x0F));
               }
               }
               """,
               fill(r"""
               {
                   CHECK_EQ(ex1_4::get_field(0x45, 4, 4), 4);   // high nibble
                   CHECK_EQ(ex1_4::get_field(0x45, 0, 4), 5);   // low nibble
                   CHECK_EQ(ex1_4::get_field(0xB6, 2, 3), @F@);
                   CHECK_EQ(ex1_4::get_field(0x12, 1, 1), 1);   // bit 1 of 0001'0010
                   CHECK_EQ(ex1_4::get_field(0x12, 0, 1), 0);
                   CHECK_EQ(ex1_4::pack_nibbles(4, 5), 0x45);
                   CHECK_EQ(ex1_4::pack_nibbles(0xF, 0x0), 0xF0);
               }
               """, F=(0xB6 >> 2) & 7),
               r"""
               Masking with `lo & 0x0F` in `pack_nibbles` is defensive: if a caller passes a value > 15, its
               extra bits would otherwise overwrite the high nibble. Note that `1u << width` with `width = 8` is
               fine here (`1u` is 32 bits wide), unlike the `<< 32` trap from §1.1.
               """, snippet_key="get_field")

    # ------------------------------------------------------------------ 1.5
    B.md(r"""
    ## 1.5 Endianness: how multi-byte integers sit in memory

    Memory is addressed per byte, so a `uint32_t` occupies 4 consecutive addresses. *Which byte goes
    first* is a CPU convention called **endianness**:

    ```
    value 0x0A0B0C0D     address:  +0   +1   +2   +3
    big-endian    (BE)             0A   0B   0C   0D   most significant byte first
    little-endian (LE)             0D   0C   0B   0A   least significant byte first
    ```

    x86-64 and ARM (as configured on phones, Macs and servers) are **little-endian**. Neither order
    is "correct"; they are simply conventions. `std::memcpy(dst, src, n)` (from `<cstring>`) copies
    `n` raw bytes, which lets you look at the in-memory representation of a value:
    """)
    B.code(r"""
    {
        uint32_t v = 0x0A0B0C0D;
        uint8_t bytes[4];
        std::memcpy(bytes, &v, 4);       // copy the 4 bytes exactly as they sit in memory
        hexdump(bytes, 4);
    }
    """)
    B.question("predict", r"""On your (little-endian) machine: `uint16_t v = 0x1234; uint8_t buf[2]; std::memcpy(buf, &v, 2);
    std::cout << std::hex << +buf[0];` — what is printed?""",
               r"""
               **`34`**. Little-endian stores the least significant byte (0x34) at the lowest address, so
               `buf = {0x34, 0x12}`. On a big-endian CPU it would print `12`. A hexdump of an integer taken from
               memory therefore looks "reversed" on x86.
               """)
    B.exercise("1.5", "Detect the host's endianness",
               r"""
               Write `host_is_little_endian()` using `memcpy` on a `uint16_t` whose value is 1: inspect which
               byte ends up non-zero.
               """,
               r"""
               namespace ex1_5 {
               bool host_is_little_endian() {
                   // TODO
                   return false;
               }
               }
               """,
               r"""
               namespace ex1_5 {
               bool host_is_little_endian() {
                   uint16_t one = 1;               // bytes are {01,00} on LE, {00,01} on BE
                   uint8_t first;
                   std::memcpy(&first, &one, 1);   // copy just the byte at the lowest address
                   return first == 1;
               }
               }
               """,
               r"""
               {
                   // The compiler knows the answer too; we compare against its built-in macro.
                   bool expected = (__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__);
                   CHECK_EQ(ex1_5::host_is_little_endian(), expected);
               }
               """,
               r"""
               The byte at the lowest address is the least significant one exactly when the host is little-endian.
               `memcpy` is the portable way to reinterpret bytes; casting pointers to unrelated types
               (`*(uint8_t*)&one` is allowed, but `*(uint32_t*)some_bytes` is not in general) runs into
               C++'s aliasing and alignment rules.
               """)

    # ------------------------------------------------------------------ 1.6
    be = [0x01, 0xBB]
    B.md(r"""
    ## 1.6 Network byte order and the portable way to read it

    Two machines exchanging a 16-bit number must agree on byte order, or an LE sender and a BE
    receiver disagree about every value. Internet protocols fix the convention: multi-byte header
    fields are transmitted **big-endian**, which is therefore called **network byte order**.

    ```
    bytes on the wire (in order):   0x12   0x34
    value:                          0x1234   =  (p[0] << 8) | p[1]
    ```

    Assembling the value from individual bytes with shifts is **portable**: it gives the same
    answer on any CPU and never performs a misaligned multi-byte load. Do *not* write
    `*(uint16_t*)p`: on LE it gives 0x3412, and if `p` is not 2-byte aligned it is undefined behaviour.

    **Pitfall:** `p[0] << 24` promotes `p[0]` to a *signed* `int`; for `p[0] ≥ 0x80` the result
    overflows it. Write `uint32_t(p[0]) << 24`.
    """)
    B.question("predict", r"""Two bytes arrive: `0x01 0xBB`. What 16-bit value do they represent in network byte order?
    What would a buggy little-endian read (`memcpy` into a `uint16_t` on x86) produce?""",
               f"""
               Network order (big-endian): `0x01BB` = **{0x01BB}**. The buggy LE read gives `0xBB01` =
               **{0xBB01}**. Byte-order bugs rarely crash; they silently produce plausible-looking wrong numbers.
               """)
    B.exercise("1.6", "read_be16, read_be32, write_be16, write_be32",
               r"""
               Implement the four big-endian helpers. You will reuse them in almost every later part.
               `write_*` store `v` into `p[0..1]` / `p[0..3]` in network byte order.
               """,
               r"""
               namespace ex1_6 {
               uint16_t read_be16(const uint8_t* p) { return 0; }   // TODO
               uint32_t read_be32(const uint8_t* p) { return 0; }   // TODO
               void write_be16(uint8_t* p, uint16_t v) { }          // TODO
               void write_be32(uint8_t* p, uint32_t v) { }          // TODO
               }
               """,
               r"""
               namespace ex1_6 {
               uint16_t read_be16(const uint8_t* p) {
                   return uint16_t((uint16_t(p[0]) << 8) | p[1]);
               }
               uint32_t read_be32(const uint8_t* p) {
                   return (uint32_t(p[0]) << 24) | (uint32_t(p[1]) << 16) |
                          (uint32_t(p[2]) << 8)  |  uint32_t(p[3]);
               }
               void write_be16(uint8_t* p, uint16_t v) {
                   p[0] = uint8_t(v >> 8);      // most significant byte first
                   p[1] = uint8_t(v & 0xFF);
               }
               void write_be32(uint8_t* p, uint32_t v) {
                   p[0] = uint8_t(v >> 24);
                   p[1] = uint8_t(v >> 16);     // the uint8_t cast keeps only the low 8 bits
                   p[2] = uint8_t(v >> 8);
                   p[3] = uint8_t(v);
               }
               }
               """,
               r"""
               {
                   const uint8_t in[] = {0x12, 0x34, 0x56, 0x78, 0xff, 0xff, 0xff, 0xfe};
                   CHECK_EQ(ex1_6::read_be16(in), 0x1234);
                   CHECK_EQ(ex1_6::read_be16(in + 2), 0x5678);
                   CHECK_EQ(ex1_6::read_be32(in), 0x12345678u);
                   CHECK_EQ(ex1_6::read_be32(in + 4), 0xfffffffeu);   // top bit set: catches signed-shift bugs

                   uint8_t out[6] = {0, 0, 0, 0, 0, 0};
                   ex1_6::write_be16(out, 0xABCD);
                   ex1_6::write_be32(out + 2, 0xC0A8010Au);
                   const uint8_t want[] = {0xab, 0xcd, 0xc0, 0xa8, 0x01, 0x0a};
                   CHECK(std::memcmp(out, want, 6) == 0);
                   hexdump(out, 6);
                   CHECK_EQ(ex1_6::read_be32(out + 2), 0xC0A8010Au);   // round trip
               }
               """,
               r"""
               Each byte is widened to the result type **before** shifting, which avoids the signed-`int`
               overflow at `<< 24`. `write_*` go the other way: shift the wanted byte down to bits 0–7 and truncate
               with a cast. These functions never ask what the host's endianness is, which is why they are portable.
               """, snippet_key="be")

    # ------------------------------------------------------------------ 1.7
    B.md(r"""
    ## 1.7 `htons`, `ntohs`, `htonl`, `ntohl`

    The POSIX header `<arpa/inet.h>` provides the classic conversion functions. Read the names as
    **h**ost **to** **n**etwork **s**hort (16-bit) / **l**ong (32-bit), and the reverse:

    ```
    htons, ntohs : uint16_t -> uint16_t      htonl, ntohl : uint32_t -> uint32_t
    little-endian host: swap the bytes       big-endian host: return the value unchanged
    ```

    They operate on *values*, not byte pointers: `htons(0x1234)` returns the number whose in-memory
    bytes are `12 34` on this host. You need them wherever an API wants a network-order *value*
    inside a struct; the socket API in Part 9 is the main example. For parsing bytes, `read_be16` and
    `memcpy` + `ntohs` are equivalent.
    """)
    B.question("predict", r"""On x86: `std::cout << std::hex << htons(0x1234) << " " << htonl(0x0A000001);`""",
               f"""
               **`3412 {int.from_bytes((0x0A000001).to_bytes(4, 'big'), 'little'):x}`**. On a little-endian host both functions reverse
               the bytes. Printing the result as a *number* on the same host therefore shows the swapped value; when stored
               to memory, however, its bytes are in network order (`12 34`).
               """)
    B.question("why", r"""On a big-endian host `htonl` does nothing. Why should portable code still call it,
    and does a single `uint8_t` field ever need conversion?""",
               r"""
               Code must compile and behave identically on both kinds of host. Calling `htonl` documents the intent and
               becomes a no-op where no swap is needed, so it costs nothing. A single byte has **no** byte order:
               endianness is about the order of bytes *within* a multi-byte value. (The order of *bits* on a
               cable is a physical-layer matter, handled by hardware and invisible to software.)
               """)
    B.exercise("1.7", "Swap bytes yourself and verify against htons/htonl",
               r"""
               * `swap16(v)`, `swap32(v)`: reverse the byte order of a value using shifts and masks.
               * `read_be16_via_ntohs(p)`: read 2 bytes with `memcpy` into a `uint16_t`, then apply `ntohs`.

               On a little-endian host `swap16` must agree with `htons`.
               """,
               r"""
               namespace ex1_7 {
               uint16_t swap16(uint16_t v) { return 0; }             // TODO
               uint32_t swap32(uint32_t v) { return 0; }             // TODO
               uint16_t read_be16_via_ntohs(const uint8_t* p) { return 0; }   // TODO
               }
               """,
               r"""
               namespace ex1_7 {
               uint16_t swap16(uint16_t v) {
                   return uint16_t((v >> 8) | (v << 8));   // truncation to 16 bits drops the overflow
               }
               uint32_t swap32(uint32_t v) {
                   return  (v >> 24)                  // byte 3 -> byte 0
                        | ((v >> 8)  & 0x0000FF00u)   // byte 2 -> byte 1
                        | ((v << 8)  & 0x00FF0000u)   // byte 1 -> byte 2
                        |  (v << 24);                 // byte 0 -> byte 3
               }
               uint16_t read_be16_via_ntohs(const uint8_t* p) {
                   uint16_t raw;
                   std::memcpy(&raw, p, 2);   // raw now holds the wire bytes in memory order
                   return ntohs(raw);         // reinterpret them as network order
               }
               }
               """,
               r"""
               {
                   CHECK_EQ(ex1_7::swap16(0x1234), 0x3412);
                   CHECK_EQ(ex1_7::swap32(0x0A0B0C0Du), 0x0D0C0B0Au);
                   CHECK_EQ(ex1_7::swap32(ex1_7::swap32(0xDEADBEEFu)), 0xDEADBEEFu);
                   bool le = (__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__);
                   if (le) {
                       CHECK_EQ(ex1_7::swap16(0xBEEF), htons(0xBEEF));
                       CHECK_EQ(ex1_7::swap32(0x0A000001u), htonl(0x0A000001u));
                   }
                   const uint8_t wire[] = {0x01, 0xbb, 0x80, 0x00};
                   CHECK_EQ(ex1_7::read_be16_via_ntohs(wire), 443);
                   CHECK_EQ(ex1_7::read_be16_via_ntohs(wire + 2), 0x8000);
               }
               """,
               r"""
               `swap32` moves each byte to its mirror position; the masks discard the bytes that slid into the wrong lane.
               Compilers recognise this pattern and emit a single `bswap` instruction, which is essentially what
               `htonl` is on x86. `memcpy` + `ntohs` works because `memcpy` preserves byte order and `ntohs`
               then performs exactly the swap that the host's endianness requires (none on BE).
               """)
    B.recap(
        ["Use exact-width unsigned types (`uint8_t`…`uint32_t`); they wrap modulo $2^n$. Print a `uint8_t` with `+b`.",
         "One hex digit = one nibble = 4 bits; one byte = two hex digits.",
         "Field extraction: `(b >> shift) & ((1u << width) - 1)`. Beware shifts ≥ the type's width and integer promotion.",
         "Endianness is the byte order of multi-byte values in memory; x86 and ARM are little-endian.",
         "Network byte order is big-endian. Read it portably with shifts (`read_be16/32`), or with `memcpy` + `ntohs/ntohl`."],
        ["why `std::cout << uint8_t(65)` prints `A`;",
         "how to extract any bit field from a byte, and why `1u << 32` is a bug;",
         "what `htons(0x1234)` returns on x86, and why;",
         "why `*(uint16_t*)p` is wrong for parsing packet bytes."])
