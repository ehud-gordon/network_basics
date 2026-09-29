import ipaddress
import struct

from nb import fill, cpp_bytes, hexdump_py, eth_header, mac_bytes


def arp_request_frame():
    src_mac = "3c:22:fb:12:ab:9e"
    arp = struct.pack("!HHBBH6s4s6s4s", 1, 0x0800, 6, 4, 1, mac_bytes(src_mac),
                      ipaddress.IPv4Address("192.168.1.10").packed, bytes(6),
                      ipaddress.IPv4Address("192.168.1.1").packed)
    payload = arp + bytes(46 - len(arp))          # pad to the 46-byte minimum
    return eth_header("ff:ff:ff:ff:ff:ff", src_mac, 0x0806) + payload


HOSTS = {"A": "02:00:00:00:00:0a", "B": "02:00:00:00:00:0b", "C": "02:00:00:00:00:0c",
         "D": "02:00:00:00:00:0d", "E": "02:00:00:00:00:0e"}
BCAST = "ff:ff:ff:ff:ff:ff"
MCAST = "01:00:5e:00:00:fb"
# (in_port, src, dst, comment)
SCRIPT = [
    (1, "A", "B", "B unknown yet"),
    (2, "B", "A", "A was learned from frame 1"),
    (1, "A", "B", "B was learned from frame 2"),
    (3, "C", BCAST, ""),
    (4, "D", "C", ""),
    (2, "B", "D", ""),
    (3, "A", "D", "A moved to port 3!"),
    (2, "B", "A", "table was updated by frame 7"),
    (3, "C", MCAST, ""),
    (4, "E", "D", "E and D share port 4 (via a hub)"),
]


def mac_of(x):
    return HOSTS.get(x, x)


def switch_sim(n_ports=4):
    table = {}
    outs = []
    for in_port, src, dst, _ in SCRIPT:
        s, d = mac_of(src), mac_of(dst)
        table[s] = in_port
        group = int(d[:2], 16) & 1
        if group or d not in table:
            out = [p for p in range(1, n_ports + 1) if p != in_port]
        elif table[d] == in_port:
            out = []
        else:
            out = [table[d]]
        outs.append(out)
    return outs


def build(B):
    B.part("5", "Link layer: Ethernet")
    B.md(r"""
    # Part 5 — Link layer: Ethernet

    **Ethernet** (IEEE 802.3) is the dominant wired link-layer protocol; Wi-Fi reuses its addressing
    and frame ideas. Its job is to deliver a **frame** from one NIC to another on the same LAN.

    ## 5.1 The Ethernet frame

    ```
    +----------+-----+---------+---------+-----------+-------------------+-------+
    | preamble | SFD | dst MAC | src MAC | EtherType |      payload      |  FCS  |
    | 7 bytes  |  1  |    6    |    6    |     2     |   46 … 1500 bytes |   4   |
    +----------+-----+---------+---------+-----------+-------------------+-------+
     consumed by the NIC     offset 0   6         12          14
     (clock sync + start)    |<------- 14-byte header ------>|
    ```

    * **Preamble + SFD** (start frame delimiter): alternating 1010… bits that let the receiver lock
      its clock, then `10101011` meaning "frame starts now". The NIC strips them; software never sees them.
    * **EtherType** names the payload's protocol: `0x0800` IPv4, `0x0806` ARP (the protocol that finds
      a MAC address from an IP address), `0x86DD` IPv6 (the newer version of IP, with 128-bit addresses).
    * **MTU** (maximum transmission unit) = the largest payload = **1500 bytes**.
    * The payload is at least **46 bytes**; shorter payloads are **padded** with zeros, so the minimum frame
      (dst … FCS) is 64 bytes.
    * **FCS** (frame check sequence): a 4-byte error-detection code over the frame (§5.5).
    """)
    B.question("compute", r"""(a) What is the largest frame from dst MAC to FCS? (b) A frame carries a 20-byte payload: how many
    padding bytes are added? (c) Counting the preamble+SFD and the mandatory 12-byte idle gap between frames, what fraction of
    the wire time carries payload for full-size frames?""",
               f"""
               (a) 6 + 6 + 2 + 1500 + 4 = **{6+6+2+1500+4} bytes**.
               (b) 46 − 20 = **{46-20} bytes** of padding (the receiver must use a length field inside the payload, such as IP's
               total length, to know where real data ends).
               (c) Per frame on the wire: 8 + 1518 + 12 = {8+1518+12} byte-times, so efficiency = 1500 / {8+1518+12} = **{1500/1538:.2%}**.
               A "1 Gb/s" Ethernet therefore delivers at most ≈ {1e9*1500/1538/1e6:.0f} Mb/s of Ethernet payload.
               """)
    B.exercise("5.1", "Frame size and padding",
               r"""
               * `padding_bytes(payload_len)`: zero-padding bytes needed (payload ≥ 46 means none).
               * `frame_bytes(payload_len)`: size from dst MAC to FCS inclusive, padding included; return 0 if
                 `payload_len > 1500` (it does not fit in one frame).
               """,
               r"""
               namespace ex5_1 {
               int padding_bytes(int payload_len) { return -1; }   // TODO
               int frame_bytes(int payload_len)   { return -1; }   // TODO
               }
               """,
               r"""
               namespace ex5_1 {
               int padding_bytes(int payload_len) {
                   return payload_len >= 46 ? 0 : 46 - payload_len;
               }
               int frame_bytes(int payload_len) {
                   if (payload_len > 1500) return 0;                          // exceeds the MTU
                   return 14 + payload_len + padding_bytes(payload_len) + 4;  // header + data + pad + FCS
               }
               }
               """,
               r"""
               {
                   CHECK_EQ(ex5_1::padding_bytes(20), 26);
                   CHECK_EQ(ex5_1::padding_bytes(46), 0);
                   CHECK_EQ(ex5_1::padding_bytes(0), 46);
                   CHECK_EQ(ex5_1::frame_bytes(20), 64);      // the minimum frame
                   CHECK_EQ(ex5_1::frame_bytes(1500), 1518);  // the maximum frame
                   CHECK_EQ(ex5_1::frame_bytes(1501), 0);     // too big
               }
               """,
               r"""
               Why a minimum at all? In the original shared-cable Ethernet a sender had to still be transmitting when news of a
               collision came back from the far end of the cable, so every frame had to last at least one round trip of the
               cable, i.e. 64 bytes. Switched full-duplex Ethernet (each cable carries both directions at once, so collisions cannot happen) no longer needs this, but the rule remains for compatibility.
               """)

    # ------------------------------------------------------------------ 5.2
    B.md(r"""
    ## 5.2 MAC addresses

    A **MAC address** is 48 bits (6 bytes), written as six two-digit hex bytes separated by colons:
    `3c:22:fb:12:ab:9e`. The first three bytes are the **OUI** (organizationally unique identifier),
    a block assigned to the manufacturer; the manufacturer numbers the last three bytes itself.
    Software handles addresses as 6 raw bytes and converts them to text only for display.
    """)
    B.provided("lib5", [("1.2", "to_hex8"), ("1.6", "be")])
    B.exercise("5.2", "Format a MAC address",
               r"""
               Write `format_mac(p)` for the 6 bytes at `p`, producing lowercase `aa:bb:cc:dd:ee:ff`.
               Use `lib5::to_hex8`.
               """,
               r"""
               namespace ex5_2 {
               std::string format_mac(const uint8_t* p) {
                   // TODO
                   return "";
               }
               }
               """,
               r"""
               namespace ex5_2 {
               std::string format_mac(const uint8_t* p) {
                   std::string s;
                   for (int i = 0; i < 6; ++i) {
                       if (i) s += ':';          // separator between bytes, not after the last
                       s += lib5::to_hex8(p[i]);
                   }
                   return s;
               }
               }
               """,
               r"""
               {
                   const uint8_t m1[6] = {0x3c, 0x22, 0xfb, 0x12, 0xab, 0x9e};
                   const uint8_t m2[6] = {0x00, 0x00, 0x0a, 0x00, 0x00, 0x01};
                   CHECK_EQ(ex5_2::format_mac(m1), "3c:22:fb:12:ab:9e");
                   CHECK_EQ(ex5_2::format_mac(m2), "00:00:0a:00:00:01");   // leading zeros kept
               }
               """,
               r"""
               The only traps are the separator (none after the last byte) and leading zeros (`0a`, not `a`); `to_hex8`
               already handles the latter.
               """, snippet_key="format_mac")

    # ------------------------------------------------------------------ 5.3
    B.md(r"""
    ## 5.3 Unicast, multicast, broadcast

    Two bits of the **first** address byte have special meanings:

    ```
    first byte:   b7 b6 b5 b4 b3 b2 [b1] [b0]
                                      |    └─ I/G bit: 0 = Individual (unicast), 1 = Group (multicast)
                                      └────── U/L bit: 0 = Universal (factory OUI), 1 = Locally administered
    ```

    * **Unicast**: I/G = 0; the frame is for one NIC.
    * **Multicast**: I/G = 1; the frame is for every NIC that joined that group.
    * **Broadcast**: `ff:ff:ff:ff:ff:ff`, the special group "everyone on the LAN" (its I/G bit is 1 too).
    * U/L = 1 marks addresses set by software, e.g. the randomised MACs phones use for privacy.

    Why bit 0? Ethernet transmits each byte least-significant bit first, so the I/G bit is the
    **very first address bit on the wire**, and hardware can start deciding before the rest arrives.
    """)
    B.exercise("5.3", "Classify a destination address",
               r"""
               Implement the three predicates on the 6 bytes at `p`.
               """,
               r"""
               namespace ex5_3 {
               bool is_broadcast(const uint8_t* p)            { return false; }   // TODO
               bool is_multicast(const uint8_t* p)            { return false; }   // TODO (broadcast counts too)
               bool is_locally_administered(const uint8_t* p) { return false; }   // TODO
               }
               """,
               r"""
               namespace ex5_3 {
               bool is_broadcast(const uint8_t* p) {
                   for (int i = 0; i < 6; ++i)
                       if (p[i] != 0xff) return false;
                   return true;
               }
               bool is_multicast(const uint8_t* p)            { return p[0] & 0x01; }   // I/G bit
               bool is_locally_administered(const uint8_t* p) { return p[0] & 0x02; }   // U/L bit
               }
               """,
               r"""
               {
                   const uint8_t bcast[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
                   const uint8_t mdns[6]  = {0x01, 0x00, 0x5e, 0x00, 0x00, 0xfb};   // IPv4 multicast group
                   const uint8_t uni[6]   = {0x3c, 0x22, 0xfb, 0x12, 0xab, 0x9e};
                   const uint8_t rnd[6]   = {0x02, 0x11, 0x22, 0x33, 0x44, 0x55};   // randomised (local) MAC
                   const uint8_t odd[6]   = {0x03, 0x00, 0x00, 0x00, 0x00, 0x01};

                   CHECK(ex5_3::is_broadcast(bcast));
                   CHECK(!ex5_3::is_broadcast(mdns));
                   CHECK(ex5_3::is_multicast(bcast));          // broadcast is a group address
                   CHECK(ex5_3::is_multicast(mdns));
                   CHECK(!ex5_3::is_multicast(uni));
                   CHECK(ex5_3::is_multicast(odd));            // 0x03 = ...0011: I/G = 1
                   CHECK(ex5_3::is_locally_administered(rnd));
                   CHECK(!ex5_3::is_locally_administered(uni));
               }
               """,
               r"""
               `p[0] & 0x01` is non-zero exactly when bit 0 is set; converting to `bool` yields `true`/`false`.
               A common mistake is testing the *last* byte or the *high* bit of the first byte, because people
               expect "first on the wire" to be the most significant bit, which it is not for Ethernet.
               """, snippet_key="mac_kind")
    B.question("predict", r"""Classify each as unicast / multicast / broadcast, and universal / local:
    `33:33:00:00:00:01`, `3a:f1:9c:00:12:34`, `01:80:c2:00:00:00`.""",
               f"""
               * `33:33:…`: 0x33 = `0011 0011`, so I/G = 1 → **multicast** (the IPv6 multicast prefix); U/L = 1.
               * `3a:f1:…`: 0x3a = `0011 1010`, so I/G = 0 → **unicast**; U/L = 1 → **locally administered**, likely a
                 phone's randomised MAC.
               * `01:80:c2:00:00:00`: I/G = 1 → **multicast** (a group used by switches to talk among themselves); U/L = 0.

               Only the lowest two bits of the *first* byte matter: convert that byte to binary and read bits 0 and 1.
               """)

    # ------------------------------------------------------------------ 5.4
    frame = arp_request_frame()
    B.md(r"""
    ## 5.4 Parsing an Ethernet header

    Parsing means reading fields at fixed **offsets** from a byte buffer: dst at 0–5, src at 6–11,
    EtherType at 12–13 (big-endian). A robust parser first checks that the buffer is long enough.

    Here is a real frame, captured as software sees it (no preamble or FCS): a broadcast carrying an ARP
    message, padded to the 46-byte minimum payload.
    """)
    B.code(fill(r"""
    namespace frames5 {
    const std::vector<uint8_t> arp_frame = {
    @BYTES@
    };
    }
    """, BYTES=cpp_bytes(frame, indent="    ")), tags=["data"])
    B.code(r"""
    hexdump(frames5::arp_frame);
    """)
    B.provided("lib5b", [("5.2", "format_mac"), ("5.3", "mac_kind")])
    B.exercise("5.4", "parse_eth",
               r"""
               Fill in `parse_eth(p, n)`. Return `std::nullopt` if `n < 14`. Copy the addresses with `std::memcpy`
               (`h.dst.data()` gives a writable pointer into a `std::array`) and read the EtherType with `lib5::read_be16`.
               """,
               r"""
               namespace ex5_4 {
               struct EthHeader {
                   std::array<uint8_t, 6> dst{};
                   std::array<uint8_t, 6> src{};
                   uint16_t ethertype = 0;
               };
               std::optional<EthHeader> parse_eth(const uint8_t* p, size_t n) {
                   // TODO
                   return std::nullopt;
               }
               }
               """,
               r"""
               namespace ex5_4 {
               struct EthHeader {
                   std::array<uint8_t, 6> dst{};
                   std::array<uint8_t, 6> src{};
                   uint16_t ethertype = 0;
               };
               std::optional<EthHeader> parse_eth(const uint8_t* p, size_t n) {
                   if (n < 14) return std::nullopt;            // too short to hold the header
                   EthHeader h;
                   std::memcpy(h.dst.data(), p + 0, 6);
                   std::memcpy(h.src.data(), p + 6, 6);
                   h.ethertype = lib5::read_be16(p + 12);      // network byte order
                   return h;
               }
               }
               """,
               fill(r"""
               {
                   const auto& f = frames5::arp_frame;
                   auto h = ex5_4::parse_eth(f.data(), f.size());
                   CHECK(h.has_value());
                   auto hh = h.value_or(ex5_4::EthHeader{});        // safe even if parsing failed
                   CHECK_EQ(lib5b::format_mac(hh.dst.data()), "@DST@");
                   CHECK_EQ(lib5b::format_mac(hh.src.data()), "@SRC@");
                   CHECK_EQ(hh.ethertype, 0x@ET@);
                   CHECK(lib5b::is_broadcast(hh.dst.data()));
                   CHECK(!ex5_4::parse_eth(f.data(), 13).has_value());   // truncated
                   std::cout << "payload bytes after the header: " << f.size() - 14 << "\n";
               }
               """, DST="ff:ff:ff:ff:ff:ff", SRC="3c:22:fb:12:ab:9e", ET="0806"),
               r"""
               The EtherType bytes are `08 06`. Read big-endian that is 0x0806 = ARP; a naive little-endian load would give
               0x0608, which is not a known protocol. Returning `std::optional` forces the caller to handle "not a valid
               header" explicitly instead of reading garbage from a short buffer.
               """, snippet_key="parse_eth")
    B.question("why", r"""Your parser reads EtherType `0x8100` from a frame captured on an office network. What happened,
    and where is the real EtherType?""",
               r"""
               `0x8100` marks an **802.1Q VLAN tag**: 4 extra bytes inserted after the source MAC (2 bytes `0x8100` plus
               2 bytes holding a 12-bit VLAN ID and a priority). The real EtherType follows at offset **16**. VLANs (virtual
               LANs) let one physical switch carry several isolated LANs. *Lesson:* never hard-code "payload starts at 14"
               without checking the EtherType.
               """)

    # ------------------------------------------------------------------ 5.5
    B.md(r"""
    ## 5.5 The FCS: a CRC in the trailer (concept only)

    The **FCS** is a **CRC-32** (cyclic redundancy check) computed by the sender over dst MAC …
    payload and appended as the 4-byte trailer. The receiving NIC recomputes it; on mismatch the frame
    is **silently dropped**. Ethernet never retransmits and never notifies anyone.

    Idea: treat the frame's bits as the coefficients of a huge polynomial over GF(2) (arithmetic
    modulo 2, where addition is XOR). Divide it by a fixed degree-32 *generator* polynomial and send
    the 32-bit **remainder**; the receiver checks that the remainder matches.

    Unlike parity, every data bit influences many check bits. CRC-32 detects **all** burst errors
    of length ≤ 32 bits and all 1-, 2- and 3-bit errors in any Ethernet-sized frame; other error
    patterns slip through with probability ≈ 2⁻³². NICs compute it in hardware at line rate.
    """)
    B.question("why", r"""A switch receives a frame whose FCS does not match. What does it do, and who eventually recovers the lost data?""",
               r"""
               It **drops** the frame and increments an error counter: no retransmission and no message to the sender.
               Recovery, if any, is left to the endpoints' **higher layers**: a reliable transport protocol notices the missing
               data and resends it; an application using unreliable delivery simply loses it. *Misconception:* "Ethernet is
               reliable because it has a CRC". Error **detection** is not error **recovery**.
               """)

    # ------------------------------------------------------------------ 5.6
    outs = switch_sim()
    B.md(r"""
    ## 5.6 How a switch learns

    A switch keeps a **MAC table** (MAC address → port). For each frame arriving on port *in*:

    1. **Learn**: record `table[src] = in`. The source address shows where that host lives, and a
       later frame from a new port overwrites the entry, so hosts can move.
    2. **Forward**:
       * destination is multicast or broadcast, or not in the table → **flood**: send out of every
         port except *in*;
       * destination known on port *in* itself → **filter**: drop it (the destination already heard it on that segment);
       * otherwise → **forward** out of that one port.

    Real switches also **age out** entries not refreshed within a few minutes. No configuration is needed;
    this is why you can plug devices into a switch and it just works.

    ```
         A(port 1)     B(port 2)     C(port 3)     D, E(port 4, via a hub)
             \             |             |             /
              +--------------- switch -----------------+
    ```
    """)
    B.provided("lib5c", [("5.3", "mac_kind"), ("given", r"""
    // "aa:bb:cc:dd:ee:ff" -> 6 bytes (assumes well-formed input); std::stoi(text, nullptr, 16) parses hex
    std::array<uint8_t, 6> parse_mac(const std::string& s) {
        std::array<uint8_t, 6> m{};
        for (int i = 0; i < 6; ++i) m[i] = uint8_t(std::stoi(s.substr(3 * i, 2), nullptr, 16));
        return m;
    }""")])
    script_rows = []
    for (in_port, src, dst, comment), out in zip(SCRIPT, outs):
        name = dst if len(dst) == 1 else ("broadcast" if dst == BCAST else "multicast")
        label = f"{src}->{name}" + (f", {comment}" if comment else "")
        script_rows.append(f'        {{{in_port}, "{mac_of(src)}", "{mac_of(dst)}", "{label}"}},')
    exp_rows = ", ".join("{" + ", ".join(map(str, o)) + "}" for o in outs)
    B.exercise("5.6", "A learning switch",
               r"""
               Implement `handle(in_port, src, dst)`: learn, then return the output ports in **ascending** order
               (an empty vector means "filtered"). Ports are numbered `1 … n_ports`. `std::map<K, V>` is an ordered
               key → value table: `table[k] = v` inserts or overwrites; `table.find(k) == table.end()` means "absent".
               For the multicast test use `lib5c::is_multicast(lib5c::parse_mac(dst).data())`.
               """,
               r"""
               namespace ex5_6 {
               struct LearningSwitch {
                   int n_ports;
                   std::map<std::string, int> table;     // MAC -> port

                   std::vector<int> handle(int in_port, const std::string& src, const std::string& dst) {
                       // TODO: learn, then flood / filter / forward
                       return {};
                   }
               };
               }
               """,
               r"""
               namespace ex5_6 {
               struct LearningSwitch {
                   int n_ports;
                   std::map<std::string, int> table;     // MAC -> port

                   std::vector<int> handle(int in_port, const std::string& src, const std::string& dst) {
                       table[src] = in_port;                                         // 1. learn (or move)
                       bool group = lib5c::is_multicast(lib5c::parse_mac(dst).data());
                       auto it = table.find(dst);
                       std::vector<int> out;
                       if (group || it == table.end()) {                             // 2a. flood
                           for (int p = 1; p <= n_ports; ++p)
                               if (p != in_port) out.push_back(p);
                       } else if (it->second != in_port) {                           // 2c. forward
                           out.push_back(it->second);
                       }                                                             // 2b. else: filter
                       return out;
                   }
               };
               }
               """,
               fill(r"""
               {
                   struct Frame { int in_port; std::string src, dst, label; };
                   std::vector<Frame> script = {
               @ROWS@
                   };
                   std::vector<std::vector<int>> expected = {@EXP@};

                   ex5_6::LearningSwitch sw{4, {}};
                   for (size_t i = 0; i < script.size(); ++i) {
                       auto out = sw.handle(script[i].in_port, script[i].src, script[i].dst);
                       std::cout << "frame " << i + 1 << " (" << script[i].label << ") in port "
                                 << script[i].in_port << " -> "
                                 << (out.empty() ? "FILTER" : out.size() > 1 ? "FLOOD" : "FORWARD");
                       for (int p : out) std::cout << " " << p;
                       std::cout << "\n";
                       CHECK_EQ(out, expected[i]);
                   }
               }
               """, ROWS="\n".join(script_rows), EXP=exp_rows),
               r"""
               Walk through the interesting frames: frame 1 floods because B is unknown; frame 2 teaches the switch where B is,
               so frame 3 is forwarded to port 2 only; frame 7 comes from A on a **new** port and silently updates the table,
               so frame 8 reaches A at its new location; frame 9 is multicast and floods; frame 10's destination D lives on the
               same port it arrived on, so it is **filtered**. D already received it through the hub.
               """)
    B.question("why", r"""Why does a switch learn only from the **source** address, never from the destination?""",
               r"""
               The source address of a frame arriving on port *p* **proves** that host is reachable via *p*: it just transmitted
               from there. A destination address says nothing about location; the host may not even exist. Learning from
               sources and flooding unknown destinations is enough, because the destination's reply (almost every protocol
               replies) teaches the switch its location. *Misconception:* "switches must be configured with MAC tables". They
               build them automatically from observed traffic.
               """)
    B.recap(
        ["Ethernet frame: preamble/SFD (hardware only), dst(6), src(6), EtherType(2), payload 46–1500 (MTU 1500), FCS(4).",
         "EtherType demultiplexes the payload: 0x0800 IPv4, 0x0806 ARP, 0x86DD IPv6 (0x8100 = VLAN tag).",
         "Bit 0 of the first MAC byte = I/G (multicast); bit 1 = U/L; ff:ff:ff:ff:ff:ff = broadcast.",
         "The FCS is a CRC-32: detection only; bad frames are silently dropped.",
         "Switches learn from source addresses; flood unknown/group destinations; filter same-port destinations."],
        ["the byte offsets of every Ethernet header field;",
         "why the I/G bit is bit 0 of the first byte;",
         "why a 20-byte payload produces a 64-byte frame;",
         "exactly what a switch does with each incoming frame, including after a host moves."])
