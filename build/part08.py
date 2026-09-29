import ipaddress
import struct

from nb import (fill, dedent, cpp_bytes, hexdump_py, ip2int, udp_datagram, tcp_segment, inet_checksum,
                pseudo_header, tcp_flags_str)
from part07 import dns_query

# ---------------------------------------------------------------- reference models
SOCKS = [  # id, listening, local_ip, local_port, remote_ip, remote_port
    (1, True, "0.0.0.0", 80, "0.0.0.0", 0),
    (2, False, "10.0.0.5", 80, "198.51.100.7", 40000),
    (3, False, "10.0.0.5", 80, "198.51.100.7", 40001),
    (4, False, "10.0.0.5", 80, "203.0.113.9", 40000),
    (5, True, "10.0.0.5", 22, "0.0.0.0", 0),
]
SEGS = [  # src_ip, src_port, dst_ip, dst_port, comment
    ("198.51.100.7", 40001, "10.0.0.5", 80, "existing connection"),
    ("203.0.113.9", 40000, "10.0.0.5", 80, "same client port as socket 2, other client IP"),
    ("192.0.2.1", 5000, "10.0.0.5", 80, "new client: goes to the listening socket"),
    ("192.0.2.1", 5001, "10.0.0.5", 22, "new SSH client"),
    ("192.0.2.1", 5002, "10.0.0.5", 8080, "nobody listening"),
]


def demux_py(seg):
    si, sp, di, dp, _ = seg
    for sid, lst, li, lp, ri, rp in SOCKS:
        if not lst and (li, lp, ri, rp) == (di, dp, si, sp):
            return sid
    for sid, lst, li, lp, ri, rp in SOCKS:
        if lst and lp == dp and (li == di or li == "0.0.0.0"):
            return sid
    return -1


STATES = ["CLOSED", "LISTEN", "SYN_SENT", "SYN_RCVD", "ESTABLISHED", "FIN_WAIT_1", "FIN_WAIT_2",
          "CLOSE_WAIT", "LAST_ACK", "TIME_WAIT"]
EVENTS = ["APP_LISTEN", "APP_CONNECT", "APP_CLOSE", "RCV_SYN", "RCV_SYN_ACK", "RCV_ACK", "RCV_FIN", "TIMEOUT_2MSL"]
FSM = {
    ("CLOSED", "APP_LISTEN"): ("LISTEN", ""),
    ("CLOSED", "APP_CONNECT"): ("SYN_SENT", "SYN"),
    ("LISTEN", "RCV_SYN"): ("SYN_RCVD", "SYN|ACK"),
    ("SYN_SENT", "RCV_SYN_ACK"): ("ESTABLISHED", "ACK"),
    ("SYN_RCVD", "RCV_ACK"): ("ESTABLISHED", ""),
    ("ESTABLISHED", "APP_CLOSE"): ("FIN_WAIT_1", "FIN"),
    ("ESTABLISHED", "RCV_FIN"): ("CLOSE_WAIT", "ACK"),
    ("FIN_WAIT_1", "RCV_ACK"): ("FIN_WAIT_2", ""),
    ("FIN_WAIT_2", "RCV_FIN"): ("TIME_WAIT", "ACK"),
    ("CLOSE_WAIT", "APP_CLOSE"): ("LAST_ACK", "FIN"),
    ("LAST_ACK", "RCV_ACK"): ("CLOSED", ""),
    ("TIME_WAIT", "TIMEOUT_2MSL"): ("CLOSED", ""),
}


def fsm_run(events):
    s, out = "CLOSED", []
    for e in events:
        s, send = FSM.get((s, e), (s, "INVALID"))
        out.append((e, s, send))
    return out


def gbn_py(n, W, lose):
    base, rounds, tx, lost, log = 0, 0, 0, set(), []
    while base < n:
        rounds += 1
        expected, parts = base, []
        for s in range(base, min(base + W, n)):
            tx += 1
            if s in lose and s not in lost:
                lost.add(s)
                parts.append(f"{s}x")
            else:
                parts.append(str(s))
                if s == expected:
                    expected += 1
        base = expected
        log.append(f"round {rounds}: sent {' '.join(parts)} | ack {base}")
    return rounds, tx, log


def cwnd_py(rtts, ssthresh, dupack, timeout):
    cwnd, out = 1, []
    for r in range(rtts):
        out.append(cwnd)
        if r in dupack:
            ssthresh = max(cwnd // 2, 2)
            cwnd = ssthresh
        elif r in timeout:
            ssthresh = max(cwnd // 2, 2)
            cwnd = 1
        elif cwnd < ssthresh:
            cwnd = min(2 * cwnd, ssthresh)
        else:
            cwnd += 1
    return out


def build(B):
    B.part("8", "Transport layer: UDP and TCP")
    B.md(r"""
    # Part 8 — Transport layer: UDP and TCP

    IP delivers packets from host to host, best-effort: packets may be lost, duplicated, reordered,
    or corrupted. The transport layer delivers data between **programs**, and TCP adds reliability on top.

    ## 8.1 Ports, multiplexing, and the 5-tuple

    A **port** (16 bits) identifies an endpoint inside a host. Servers **listen** on well-known
    ports (0–1023, e.g. 53 DNS, 80 HTTP); clients use an **ephemeral** port that the OS picks from
    a high range (Linux: 32768–60999). A **socket** is the OS object a program uses as an endpoint.

    * **Multiplexing**: many programs share one IP address; the port field separates their data.
    * **Demultiplexing**, UDP: the destination (IP, port) alone selects the socket.
    * **Demultiplexing**, TCP: a *connection* is identified by the **5-tuple**
      (protocol, source IP, source port, destination IP, destination port). A segment that matches
      no connection but targets a **listening** socket's port starts a new connection.

    ```
    server 10.0.0.5:80  ── listening socket (accepts new connections)
                        ├── conn: 198.51.100.7:40000  <->  10.0.0.5:80
                        ├── conn: 198.51.100.7:40001  <->  10.0.0.5:80
                        └── conn: 203.0.113.9:40000   <->  10.0.0.5:80
    ```
    A listening socket bound to `0.0.0.0` (`INADDR_ANY`) accepts on every local address.
    """)
    B.provided("lib8", [("1.6", "be"), ("6.1", "ipv4_text")])
    demux_ans = [demux_py(s) for s in SEGS]
    B.exercise("8.1", "Demultiplex TCP segments to sockets",
               r"""
               `demux_tcp(socks, seg)` returns the id of the socket that receives the segment:
               1. a **connected** socket whose (local IP, local port, remote IP, remote port) equals the segment's
                  (dst IP, dst port, src IP, src port);
               2. otherwise a **listening** socket on the destination port whose local IP is the destination IP or `0`;
               3. otherwise `-1` (the kernel would answer with a reset).
               """,
               r"""
               namespace ex8_1 {
               struct Sock { int id; bool listening; uint32_t local_ip; uint16_t local_port; uint32_t remote_ip; uint16_t remote_port; };
               struct Seg  { uint32_t src_ip; uint16_t src_port; uint32_t dst_ip; uint16_t dst_port; };
               int demux_tcp(const std::vector<Sock>& socks, const Seg& s) {
                   // TODO
                   return 0;
               }
               }
               """,
               r"""
               namespace ex8_1 {
               struct Sock { int id; bool listening; uint32_t local_ip; uint16_t local_port; uint32_t remote_ip; uint16_t remote_port; };
               struct Seg  { uint32_t src_ip; uint16_t src_port; uint32_t dst_ip; uint16_t dst_port; };
               int demux_tcp(const std::vector<Sock>& socks, const Seg& s) {
                   for (const auto& k : socks)                              // 1. exact 5-tuple match
                       if (!k.listening && k.local_ip == s.dst_ip && k.local_port == s.dst_port &&
                           k.remote_ip == s.src_ip && k.remote_port == s.src_port)
                           return k.id;
                   for (const auto& k : socks)                              // 2. a listener on that port
                       if (k.listening && k.local_port == s.dst_port && (k.local_ip == s.dst_ip || k.local_ip == 0))
                           return k.id;
                   return -1;                                               // 3. nobody: reset
               }
               }
               """,
               fill(r"""
               {
                   auto ip = [](const char* s) { return lib8::parse_ipv4(s).value_or(0); };
                   std::vector<ex8_1::Sock> socks = {
               @SOCKS@
                   };
                   std::vector<ex8_1::Seg> segs = {
               @SEGS@
                   };
                   std::vector<int> want = {@WANT@};
                   for (size_t i = 0; i < segs.size(); ++i)
                       CHECK_EQ(ex8_1::demux_tcp(socks, segs[i]), want[i]);
               }
               """, SOCKS="\n".join(f'        {{{i}, {str(l).lower()}, ip("{li}"), {lp}, ip("{ri}"), {rp}}},'
                                    for i, l, li, lp, ri, rp in SOCKS),
                    SEGS="\n".join(f'        {{ip("{a}"), {b}, ip("{c}"), {d}}},   // {cm}' for a, b, c, d, cm in SEGS),
                    WANT=", ".join(map(str, demux_ans))),
               r"""
               The exact-match pass must come first: segments of established connections also target port 80, and without that
               precedence every segment would land on the listener. Sockets 2 and 4 share client port 40000 but differ in client
               IP, so the full 5-tuple is needed. This is how one server port handles thousands of simultaneous clients.
               """)
    B.question("compute", r"""A client host with one IP address opens connections to a single server `203.0.113.10:443`.
    Using Linux's default ephemeral range 32768–60999, how many simultaneous connections can it have to that one server endpoint? Why?""",
               f"""
               **{60999 - 32768 + 1}**. Four of the five tuple elements (protocol, client IP, server IP, server port) are fixed, so
               only the client port can differ, and there are 60999 − 32768 + 1 = {60999 - 32768 + 1} of them. The server, by
               contrast, can hold connections from millions of clients on its one port 443, because their IPs and ports differ.
               Proxies that open many connections to one backend hit this limit.
               """)

    # ------------------------------------------------------------------ 8.2 UDP
    q = dns_query(0x1a2b, "www.example.com", 1)
    udp = udp_datagram("192.168.1.23", "192.168.1.1", 53000, 53, q)
    B.md(r"""
    ## 8.2 UDP: the minimal transport

    **UDP** (User Datagram Protocol) adds almost nothing to IP: ports and an optional checksum.
    Each `send` becomes one **datagram**, delivered whole or not at all, possibly out of order, and
    with no retransmission, no connection, and no rate control.

    ```
    byte  0          2          4          6          8
       +----------+----------+----------+----------+------------ ...
       | src port | dst port |  length  | checksum |  data
       +----------+----------+----------+----------+------------ ...
       length = header (8) + data, in bytes
    ```

    Used where speed or simplicity beats reliability, or where the application handles loss
    itself: DNS, DHCP, voice and video calls, games, and time synchronisation.
    Here is the DNS query from Part 7 inside a UDP datagram (IP header omitted):
    """)
    B.code(fill(r"""
    namespace frames8 {
    // UDP datagram 192.168.1.23:53000 -> 192.168.1.1:53 carrying a DNS query
    const std::vector<uint8_t> udp_dns = {
    @B@
    };
    }
    """, B=cpp_bytes(udp, indent="    ")), tags=["data"])
    B.code(r"""
    hexdump(frames8::udp_dns);
    """)
    B.exercise("8.2", "Parse a UDP header",
               r"""
               `parse_udp(p, n)`: return `std::nullopt` if `n < 8`, or if the length field is `< 8` or `> n`.
               """,
               r"""
               namespace ex8_2 {
               struct UdpHeader { uint16_t src_port = 0, dst_port = 0, length = 0, checksum = 0; };
               std::optional<UdpHeader> parse_udp(const uint8_t* p, size_t n) {
                   // TODO
                   return std::nullopt;
               }
               }
               """,
               r"""
               namespace ex8_2 {
               struct UdpHeader { uint16_t src_port = 0, dst_port = 0, length = 0, checksum = 0; };
               std::optional<UdpHeader> parse_udp(const uint8_t* p, size_t n) {
                   if (n < 8) return std::nullopt;
                   UdpHeader h;
                   h.src_port = lib8::read_be16(p);
                   h.dst_port = lib8::read_be16(p + 2);
                   h.length   = lib8::read_be16(p + 4);
                   h.checksum = lib8::read_be16(p + 6);
                   if (h.length < 8 || h.length > n) return std::nullopt;   // inconsistent length
                   return h;
               }
               }
               """,
               fill(r"""
               {
                   const auto& d = frames8::udp_dns;
                   auto h = ex8_2::parse_udp(d.data(), d.size()).value_or(ex8_2::UdpHeader{});
                   CHECK_EQ(h.src_port, 53000);
                   CHECK_EQ(h.dst_port, 53);
                   CHECK_EQ(h.length, @LEN@);
                   CHECK_EQ(h.checksum, 0x@CS@);
                   CHECK(!ex8_2::parse_udp(d.data(), 7).has_value());
                   CHECK(!ex8_2::parse_udp(d.data(), 20).has_value());          // length field says @LEN@ > 20
                   std::cout << "payload = " << h.length - 8 << " bytes of DNS\n";
               }
               """, LEN=len(udp), CS=f"{int.from_bytes(udp[6:8], 'big'):04x}"),
               r"""
               UDP's length field is redundant with IP's total length, but the parser must still check that the two are
               consistent. A datagram claiming more bytes than were received is truncated or malicious.
               """, snippet_key="parse_udp")
    B.question("compute", fill(r"""A UDP header reads `c3 50 00 35 00 25 1f 9a`. Give the source port, destination port,
    and payload size. Which application is probably involved?""", ),
               f"""
               Source port 0xc350 = **{0xc350}** (ephemeral), destination port 0x0035 = **{0x35}** → **DNS**; length 0x0025 =
               {0x25} → payload = {0x25} − 8 = **{0x25 - 8} bytes**. The checksum is `1f9a`. A destination port in the
               well-known range identifies the service, while the source port is the client's ephemeral one.
               """)

    # ------------------------------------------------------------------ 8.3 checksum with pseudo-header
    udp_zero = udp[:6] + b"\x00\x00" + udp[8:]
    ph = pseudo_header("192.168.1.23", "192.168.1.1", 17, len(udp))
    B.md(r"""
    ## 8.3 The transport checksum and the pseudo-header

    UDP and TCP checksums use the same Internet checksum as IPv4 (§6.7), but computed over a
    12-byte **pseudo-header** followed by the whole segment (header + data):

    ```
    pseudo-header (never transmitted, only summed)
    +-----------------------------------------------+
    |               source IP address               |
    +-----------------------------------------------+
    |             destination IP address            |
    +-----------+-----------+-----------------------+
    |   zero    | protocol  |  UDP/TCP length       |   protocol: 6 = TCP, 17 = UDP
    +-----------+-----------+-----------------------+
    ```

    Including the IP addresses lets the receiver detect a segment delivered to the **wrong host**
    (e.g. corrupted addresses). For UDP over IPv4 a checksum of `0` means "none computed", so a
    computed value of `0` is sent as `0xFFFF`.
    """)
    B.provided("lib8b", [("6.7", "checksum")])
    B.exercise("8.3", "Compute and verify a UDP/TCP checksum",
               r"""
               `transport_checksum(src_ip, dst_ip, proto, seg, len)`: build pseudo-header + segment in a `std::vector<uint8_t>`,
               then return `lib8b::internet_checksum` over it. Verifying a received segment means that this returns `0`.
               """,
               r"""
               namespace ex8_3 {
               uint16_t transport_checksum(uint32_t src_ip, uint32_t dst_ip, uint8_t proto,
                                           const uint8_t* seg, size_t len) {
                   // TODO
                   return 0xFFFF;
               }
               }
               """,
               r"""
               namespace ex8_3 {
               uint16_t transport_checksum(uint32_t src_ip, uint32_t dst_ip, uint8_t proto,
                                           const uint8_t* seg, size_t len) {
                   std::vector<uint8_t> buf(12);
                   lib8::write_be32(&buf[0], src_ip);
                   lib8::write_be32(&buf[4], dst_ip);
                   buf[8] = 0;
                   buf[9] = proto;
                   lib8::write_be16(&buf[10], uint16_t(len));
                   buf.insert(buf.end(), seg, seg + len);          // then the whole segment
                   return lib8b::internet_checksum(buf.data(), buf.size());
               }
               }
               """,
               fill(r"""
               {
                   auto ip = [](const char* s) { return lib8::parse_ipv4(s).value_or(0); };
                   uint32_t src = ip("192.168.1.23"), dst = ip("192.168.1.1");
                   const auto& d = frames8::udp_dns;
                   CHECK_EQ(ex8_3::transport_checksum(src, dst, 17, d.data(), d.size()), 0);     // verify: sums to 0

                   std::vector<uint8_t> z = d;  z[6] = 0; z[7] = 0;                             // sender's view
                   CHECK_EQ(ex8_3::transport_checksum(src, dst, 17, z.data(), z.size()), 0x@CS@);

                   uint32_t wrong_dst = ip("192.168.1.2");                                      // misdelivered
                   CHECK(ex8_3::transport_checksum(src, wrong_dst, 17, d.data(), d.size()) != 0);
               }
               """, CS=f"{inet_checksum(ph + udp_zero):04x}"),
               r"""
               Reusing the IPv4 checksum function is the point: one algorithm, applied to a different byte range. The last check
               shows the pseudo-header's purpose: the payload bytes are intact, but a receiver at the wrong address rejects the
               segment. That is also why NAT (§7.2) must patch transport checksums when it rewrites addresses.
               """, snippet_key="transport_checksum")

    # ------------------------------------------------------------------ 8.4 byte stream
    isn = 1000
    lens = [100, 200, 50]
    seqs = []
    nxt = isn + 1
    for l in lens:
        seqs.append(nxt)
        nxt += l
    B.md(r"""
    ## 8.4 TCP: a reliable byte stream

    **TCP** (Transmission Control Protocol) gives two programs a **connection** carrying a reliable,
    in-order **byte stream** in each direction. The stream has **no message boundaries**: two
    `send()` calls of 5 bytes may arrive as one 10-byte `recv()`, or as 3 + 7.

    Every byte of the stream is numbered:
    * the **sequence number** in a segment is the number of its **first** data byte;
    * each side picks a random **ISN** (initial sequence number); the connection-opening **SYN** and
      the closing **FIN** each consume one number;
    * the **acknowledgment number** is the number of the **next byte expected**. It is *cumulative*:
      "I have everything before this".

    ```
    ISN = 1000:   SYN uses 1000 | data bytes 1001..1100 | 1101..1300 | ...
    segment:       [seq=1001, 100 bytes] -> receiver answers ack=1101
    ```
    """)
    B.question("compute", fill(r"""A client's ISN is @ISN@. After the SYN it sends three data segments of @L0@, @L1@ and @L2@ bytes.
    What is the sequence number of each segment, and what ACK number does the server send once all have arrived? If only the second
    segment is lost, what ACK does the server send after receiving the first and the third?""",
                                    ISN=isn, L0=lens[0], L1=lens[1], L2=lens[2]),
               f"""
               Sequence numbers: **{seqs[0]}, {seqs[1]}, {seqs[2]}**; final ACK = **{nxt}** (the next byte expected).
               With the second segment lost, the server can only acknowledge contiguous data, so both ACKs say **{seqs[1]}**. The
               repeated ACK (a *duplicate ACK*) tells the sender that something after byte {seqs[1] - 1} is missing.

               *Misconceptions:* (1) sequence numbers count **bytes**, not segments; (2) the ACK number is the *next* byte expected,
               not the last one received; (3) the SYN consumes a sequence number, so data starts at ISN+1.
               """)

    # ------------------------------------------------------------------ 8.5 TCP header
    synack = tcp_segment("93.184.216.34", "192.168.1.23", 80, 51514, 0x7e3f1a02, 0x0000f1a3, 0x12, 65160,
                         options=bytes([2, 4, 0x05, 0xb4]))
    get = b"GET / HTTP/1.0\r\n\r\n"
    data = tcp_segment("192.168.1.23", "93.184.216.34", 51514, 80, 0x0000f1a3, 0x7e3f1a03, 0x18, 502, payload=get)
    B.md(r"""
    ## 8.5 The TCP header

    ```
    byte  0          1          2          3
       +----------+----------+----------+----------+
     0 |     source port     |  destination port   |
       +---------------------+---------------------+
     4 |              sequence number              |
       +-------------------------------------------+
     8 |           acknowledgment number           |
       +-----+----+----------+---------------------+
    12 | off |rsv |  flags   |       window        |   off = data offset: header length in 32-bit words (5..15)
       +-----+----+----------+---------------------+
    16 |      checksum       |   urgent pointer    |
       +---------------------+---------------------+
    20 |      options (if off > 5) ...             |   e.g. MSS: kind 2, length 4, 16-bit value
    ```

    Flags (byte 13, bit 7 → bit 0): `CWR ECE URG ACK PSH RST SYN FIN`.
    **SYN** opens a connection; **ACK** means the acknowledgment field is valid (set on every segment after the first);
    **FIN**: "I have finished sending"; **RST**: abort; **PSH**: deliver to the application promptly;
    URG/ECE/CWR are rarely relevant here. **window**: how many bytes the receiver can accept (§8.10).
    **MSS** (maximum segment size): the largest payload the sender of the option wants to receive per segment.
    """)
    B.code(fill(r"""
    namespace frames8b {
    // SYN|ACK from 93.184.216.34:80 to 192.168.1.23:51514, with an MSS option (data offset 6)
    const std::vector<uint8_t> tcp_synack = {
    @A@
    };
    // PSH|ACK carrying an HTTP request
    const std::vector<uint8_t> tcp_data = {
    @D@
    };
    }
    """, A=cpp_bytes(synack, indent="    "), D=cpp_bytes(data, indent="    ")), tags=["data"])
    B.code(r"""
    hexdump(frames8b::tcp_synack);
    """)
    B.provided("lib8c", [("1.4", "get_field")])
    B.exercise("8.5", "Parse a TCP header and decode the flags",
               r"""
               * `parse_tcp(p, n)`: return `std::nullopt` if `n < 20`, `data_offset < 5`, or the header does not fit in `n`.
               * `flags_to_string(f)`: flag names joined by `|`, **least-significant bit first** (`FIN`, `SYN`, `RST`, `PSH`,
                 `ACK`, `URG`, `ECE`, `CWR`), so that 0x12 → `"SYN|ACK"`, matching Wireshark. Return `"none"` for 0.
               """,
               r"""
               namespace ex8_5 {
               struct TcpHeader {
                   uint16_t src_port = 0, dst_port = 0, window = 0, checksum = 0, urgent = 0;
                   uint32_t seq = 0, ack = 0;
                   uint8_t data_offset = 0, flags = 0;
                   size_t header_len() const { return size_t(data_offset) * 4; }
               };
               std::optional<TcpHeader> parse_tcp(const uint8_t* p, size_t n) {
                   // TODO
                   return std::nullopt;
               }
               std::string flags_to_string(uint8_t f) {
                   // TODO
                   return "";
               }
               }
               """,
               r"""
               namespace ex8_5 {
               struct TcpHeader {
                   uint16_t src_port = 0, dst_port = 0, window = 0, checksum = 0, urgent = 0;
                   uint32_t seq = 0, ack = 0;
                   uint8_t data_offset = 0, flags = 0;
                   size_t header_len() const { return size_t(data_offset) * 4; }
               };
               std::optional<TcpHeader> parse_tcp(const uint8_t* p, size_t n) {
                   if (n < 20) return std::nullopt;
                   TcpHeader h;
                   h.src_port    = lib8::read_be16(p);
                   h.dst_port    = lib8::read_be16(p + 2);
                   h.seq         = lib8::read_be32(p + 4);
                   h.ack         = lib8::read_be32(p + 8);
                   h.data_offset = lib8c::get_field(p[12], 4, 4);   // high nibble of byte 12
                   h.flags       = p[13];
                   h.window      = lib8::read_be16(p + 14);
                   h.checksum    = lib8::read_be16(p + 16);
                   h.urgent      = lib8::read_be16(p + 18);
                   if (h.data_offset < 5 || h.header_len() > n) return std::nullopt;
                   return h;
               }
               std::string flags_to_string(uint8_t f) {
                   static const char* names[8] = {"FIN", "SYN", "RST", "PSH", "ACK", "URG", "ECE", "CWR"};
                   std::string s;
                   for (int i = 0; i < 8; ++i) {
                       if (!(f & (1u << i))) continue;
                       if (!s.empty()) s += "|";
                       s += names[i];
                   }
                   return s.empty() ? "none" : s;
               }
               }
               """,
               fill(r"""
               {
                   const auto& a = frames8b::tcp_synack;
                   auto h = ex8_5::parse_tcp(a.data(), a.size()).value_or(ex8_5::TcpHeader{});
                   CHECK_EQ(h.src_port, 80);
                   CHECK_EQ(h.dst_port, 51514);
                   CHECK_EQ(h.seq, 0x7e3f1a02u);
                   CHECK_EQ(h.ack, 0x0000f1a3u);
                   CHECK_EQ(h.header_len(), 24u);                       // data offset 6: 4 bytes of options
                   CHECK_EQ(h.window, 65160);
                   CHECK_EQ(ex8_5::flags_to_string(h.flags), "@F1@");

                   const auto& d = frames8b::tcp_data;
                   auto h2 = ex8_5::parse_tcp(d.data(), d.size()).value_or(ex8_5::TcpHeader{});
                   CHECK_EQ(ex8_5::flags_to_string(h2.flags), "@F2@");
                   CHECK_EQ(d.size() - h2.header_len(), @PL@u);           // payload = the HTTP request
                   CHECK_EQ(ex8_5::flags_to_string(0x11), "@F3@");
                   CHECK_EQ(ex8_5::flags_to_string(0x04), "RST");
                   CHECK_EQ(ex8_5::flags_to_string(0x00), "none");
                   CHECK(!ex8_5::parse_tcp(a.data(), 22).has_value());   // options cut off
               }
               """, F1=tcp_flags_str(0x12), F2=tcp_flags_str(0x18), F3=tcp_flags_str(0x11), PL=len(get)),
               r"""
               The data offset is exactly the IPv4 IHL pattern: a 4-bit count of 32-bit words. Checking that the full header,
               options included, fits in the buffer prevents reading options past the end. Note how the SYN|ACK acknowledges
               `0x0000f1a3`, one more than the client's ISN, because the SYN consumed one sequence number.
               """, snippet_key="parse_tcp")
    B.question("compute", r"""Byte 12 of a TCP header is `0x80` and byte 13 is `0x10`. What is the header length, which flags are set,
    and what is likely in the options?""",
               f"""
               Data offset = 0x8 = 8 words = **32 bytes** → 12 bytes of options. Flags 0x10 = **ACK** only, an ordinary segment of
               an established connection. On Linux the 12 option bytes are typically NOP, NOP, and a 10-byte *timestamp* option
               (used for RTT measurement). *Misconception:* reading `0x80` as 128 bytes or 8 bytes; the high nibble counts **words**.
               """)

    # ------------------------------------------------------------------ 8.6 handshake
    B.md(r"""
    ## 8.6 The three-way handshake

    ```
    client (CLOSED)                                   server (LISTEN)
       |---- SYN        seq=x ------------------------->|   SYN_SENT        -> SYN_RCVD
       |<--- SYN|ACK    seq=y, ack=x+1 -----------------|
       |---- ACK        seq=x+1, ack=y+1 -------------->|   ESTABLISHED     -> ESTABLISHED
    ```

    Each SYN carries the sender's random ISN and options such as MSS and window scaling (§8.10).
    Each ACK proves that the other side's ISN arrived. Data may start with the third segment.
    A SYN to a port with no listener is answered with **RST** ("connection refused").
    """)
    B.question("why", r"""Why three segments? What could go wrong with a two-way handshake (SYN, then SYN|ACK, and the server
    immediately considers the connection open)?""",
               r"""
               Both directions need their ISN **confirmed**: the client's ISN is acknowledged by the SYN|ACK, and the server's ISN
               only by the final ACK. With two messages the server never learns whether its ISN arrived. Worse, an **old duplicate
               SYN** from a long-dead connection, delayed in the network, would make the server open a bogus connection and allocate
               resources. With three messages the client, seeing a SYN|ACK for a connection it never started, answers RST.
               ISNs are random so that old segments, and attackers who cannot see the traffic, cannot guess valid sequence numbers.
               """)

    # ------------------------------------------------------------------ 8.7 teardown
    ports = 60999 - 32768 + 1
    B.md(r"""
    ## 8.7 Teardown and `TIME_WAIT`

    Each direction is closed independently with a FIN, which the other side ACKs (four segments; the
    middle two are often combined):

    ```
    A (closes first: "active close")                    B
       |---- FIN seq=u ------------------------------->|   A: FIN_WAIT_1   B: CLOSE_WAIT
       |<--- ACK ack=u+1 ------------------------------|   A: FIN_WAIT_2   (B may keep sending data)
       |<--- FIN seq=v --------------------------------|                   B: LAST_ACK
       |---- ACK ack=v+1 ----------------------------->|   A: TIME_WAIT    B: CLOSED
       |   ... wait 2 x MSL (Linux: 60 s) ...          |
       A: CLOSED
    ```

    **MSL** (maximum segment lifetime) is the longest a segment is assumed to survive in the network.
    The side that closes first stays in **TIME_WAIT** for 2 × MSL, for two reasons:
    (1) if its final ACK is lost, B retransmits its FIN, and A must still be there to re-ACK it;
    (2) delayed segments of this connection must die before the same 5-tuple can be reused.
    **RST** instead aborts a connection immediately, with no handshake.
    """)
    B.question("compute", fill(r"""A load-testing client opens and actively closes short connections to one server endpoint as fast as possible.
    Each closed connection's port sits in TIME_WAIT for 60 s. With @P@ ephemeral ports, what sustained rate of new connections
    can it achieve?""", P=ports),
               f"""
               {ports} ports / 60 s ≈ **{ports / 60:.0f} connections per second**. Beyond that, `connect()` fails with "address
               not available" because every port for that 5-tuple is still in TIME_WAIT. Remedies: keep connections alive and
               reuse them (HTTP keep-alive, connection pools), let the *server* close first, or spread load over more
               IPs/ports. *Misconception:* "TIME_WAIT is a bug to disable". It protects against stale segments corrupting a new
               connection.
               """)

    # ------------------------------------------------------------------ 8.8 state machine
    client_ev = ["APP_CONNECT", "RCV_SYN_ACK", "APP_CLOSE", "RCV_ACK", "RCV_FIN", "TIMEOUT_2MSL"]
    server_ev = ["APP_LISTEN", "RCV_SYN", "RCV_ACK", "RCV_FIN", "APP_CLOSE", "RCV_ACK"]
    bad_ev = ["RCV_ACK", "APP_CONNECT", "RCV_FIN"]
    runs = [("client", client_ev, fsm_run(client_ev)), ("server", server_ev, fsm_run(server_ev)),
            ("bad", bad_ev, fsm_run(bad_ev))]
    fsm_md = "\n".join(f"    {s:<12} + {e:<13} -> {n:<12} send {a or '(nothing)'}" for (s, e), (n, a) in FSM.items())
    B.md(r"""
    ## 8.8 A simplified TCP state machine

    TCP's connection life cycle is a finite-state machine. A simplified version (ignoring simultaneous
    open and close, and RST) has these transitions; anything else is **invalid** in our model:

    ```
    @FSM@
    ```
    """.replace("@FSM@", fsm_md.strip()))
    enum_states = ", ".join(STATES)
    enum_events = ", ".join(EVENTS)
    names_s = ", ".join(f'"{s}"' for s in STATES)
    names_e = ", ".join(f'"{e}"' for e in EVENTS)
    common = dedent(fill(r"""
    enum class State { @ES@ };
    enum class Event { @EE@ };
    const char* name(State s) { static const char* n[] = {@NS@}; return n[int(s)]; }
    const char* name(Event e) { static const char* n[] = {@NE@}; return n[int(e)]; }
    struct Transition { State next; std::string send; };   // send: "SYN", "SYN|ACK", "ACK", "FIN", "" or "INVALID"
    """, ES=enum_states, EE=enum_events, NS=names_s, NE=names_e))
    sol_body = "\n".join(
        f'    if (s == State::{s} && e == Event::{e}) return {{State::{n}, "{a}"}};' for (s, e), (n, a) in FSM.items())
    B.exercise("8.8", "Run the TCP state machine",
               r"""
               Implement `step(s, e)` from the table above. For a pair not in the table return `{s, "INVALID"}`: the state is unchanged.
               (`enum class` is a scoped enumeration: write `State::LISTEN`; `int(s)` gives its index.)
               """,
               "namespace ex8_8 {\n" + common + r"""
Transition step(State s, Event e) {
    // TODO
    return {s, ""};
}
}""",
               "namespace ex8_8 {\n" + common + "\nTransition step(State s, Event e) {\n"
               + sol_body.replace("\n    ", "\n    ") + '\n    return {s, "INVALID"};   // not allowed in this state\n}\n}',
               fill(r"""
               {
                   using ex8_8::State; using ex8_8::Event;
                   struct Run { const char* who; std::vector<Event> events; std::vector<std::string> want; };
                   std::vector<Run> runs = {
               @RUNS@
                   };
                   for (const auto& r : runs) {
                       State s = State::CLOSED;
                       std::vector<std::string> got;
                       std::cout << r.who << ":\n";
                       for (Event e : r.events) {
                           auto t = ex8_8::step(s, e);
                           std::cout << "  " << ex8_8::name(s) << " + " << ex8_8::name(e) << " -> " << ex8_8::name(t.next)
                                     << (t.send.empty() ? "" : "   send " + t.send) << "\n";
                           got.push_back(std::string(ex8_8::name(t.next)) + "/" + t.send);
                           s = t.next;
                       }
                       CHECK_EQ(got, r.want);
                   }
               }
               """, RUNS="\n".join(
                   f'        {{"{who}", {{{", ".join("Event::" + e for e in evs)}}}, {{{", ".join(chr(34) + n + "/" + a + chr(34) for _, n, a in out)}}}}},'
                   for who, evs, out in runs)),
               r"""
               A table-driven state machine is easy to audit against a specification; real kernels encode the same diagram (from
               RFC 9293, the current TCP specification) with more states (`CLOSING` for simultaneous close) and more events (RST,
               timeouts). Note which side ends in `TIME_WAIT`: the one that sent the **first** FIN (here the client), while the
               passive closer goes through `CLOSE_WAIT` → `LAST_ACK`. A server with thousands of sockets stuck in `CLOSE_WAIT` has
               an application bug: it never called `close()`.
               """)

    # ------------------------------------------------------------------ 8.9 reliability
    L, R, rtt = 1500 * 8, 1e9, 0.030
    u_sw = (L / R) / (rtt + L / R)
    W = 100
    u_w = min(1.0, W * (L / R) / (rtt + L / R))
    rounds, tx, log = gbn_py(10, 4, {5})
    rounds0, tx0, log0 = gbn_py(10, 4, set())
    B.md(r"""
    ## 8.9 Reliability: from stop-and-wait to sliding windows

    Reliability rests on three mechanisms: **acknowledgements**, a **retransmission timer** (resend
    if no ACK arrives within about one RTT plus a margin), and **sequence numbers** (so that the
    receiver can discard duplicates and reorder).

    **Stop-and-wait** sends one segment and waits for its ACK. The link is then busy only a tiny
    fraction of the time:
    $U = \dfrac{L/R}{\text{RTT} + L/R}$.

    A **sliding window** allows up to $W$ unacknowledged segments *in flight*, so $U$ is multiplied by $W$
    (capped at 1). To fill the pipe, $W \cdot L$ must reach the **BDP** (§2.7).

    ```
    seq:   0   1   2   3 | 4   5   6   7 | 8   9
          [ acked        ][ in flight, W=4 ][ not yet sent ]
                           ^ base = oldest unacked; slides right as ACKs arrive
    ```

    **Go-Back-N**: the receiver accepts only in-order data and sends cumulative ACKs; after a loss
    the sender resends *everything* from the lost segment on. **Selective repeat** buffers
    out-of-order data and resends only what is missing. TCP sits in between: cumulative ACKs, out-of-order
    buffering, and **fast retransmit** after 3 duplicate ACKs, without waiting for the timer.
    """)
    B.question("compute", r"""1 Gb/s link, RTT 30 ms, 1500-byte segments. What is the utilisation with stop-and-wait? With a window of
    100 segments? How many segments must be in flight to fill the link?""",
               f"""
               $L/R$ = 12 µs. Stop-and-wait: $U = 12\\,\\mu s / 30.012\\,\\text{{ms}}$ ≈ **{u_sw:.5f}** ({u_sw*1e9/1e6:.2f} Mb/s of 1000).
               Window 100: $U$ ≈ **{u_w:.4f}** ({u_w*1e3:.0f} Mb/s). To fill the link: $W \\ge (RTT + L/R)/(L/R)$ =
               **{(rtt + L / R) / (L / R):.0f} segments** ≈ BDP / L = {R*rtt/8/1500:.0f}. Pipelining is not an optimisation;
               without it, long paths are unusable.
               """)
    B.exercise("8.9", "Simulate Go-Back-N with a scripted loss",
               fill(r"""
               Simulate rounds (one RTT each). In every round the sender transmits all segments `base … min(base+W, n)−1`.
               A segment in `lose` is lost the **first** time it is sent (log it with an `x` suffix, e.g. `5x`). The receiver
               accepts a segment only if it equals `expected` (then `expected++`); anything else is discarded. At the end of
               the round the cumulative ACK is `expected`, and `base = expected`. Log each round exactly as
               `round <r>: sent <segments> | ack <base>`. Return the log; count rounds and transmissions in the out-parameters.

               With `n=10, W=4, lose={5}` the log is:
               ```
               @LOG@
               ```
               (`std::set<int>` is an ordered set; `s.count(x)` tests membership and `s.insert(x)` adds.)
               """, LOG="\n".join(log)),
               r"""
               namespace ex8_9 {
               std::vector<std::string> go_back_n(int n, int W, const std::set<int>& lose, int& rounds, int& transmissions) {
                   rounds = 0; transmissions = 0;
                   // TODO
                   return {};
               }
               }
               """,
               r"""
               namespace ex8_9 {
               std::vector<std::string> go_back_n(int n, int W, const std::set<int>& lose, int& rounds, int& transmissions) {
                   rounds = 0; transmissions = 0;
                   std::vector<std::string> log;
                   std::set<int> already_lost;
                   int base = 0;
                   while (base < n) {
                       ++rounds;
                       int expected = base;
                       std::string sent;
                       for (int s = base; s < std::min(base + W, n); ++s) {
                           ++transmissions;
                           if (!sent.empty()) sent += " ";
                           if (lose.count(s) && !already_lost.count(s)) {   // lost on its first transmission
                               already_lost.insert(s);
                               sent += std::to_string(s) + "x";
                           } else {
                               sent += std::to_string(s);
                               if (s == expected) ++expected;               // in order: accept
                           }                                                // else: out of order, discarded
                       }
                       base = expected;                                     // cumulative ACK
                       log.push_back("round " + std::to_string(rounds) + ": sent " + sent + " | ack " + std::to_string(base));
                   }
                   return log;
               }
               }
               """,
               fill(r"""
               {
                   int rounds = 0, tx = 0;
                   auto log = ex8_9::go_back_n(10, 4, {5}, rounds, tx);
                   for (const auto& line : log) std::cout << line << "\n";
                   CHECK_EQ(log, (std::vector<std::string>{@LOG@}));
                   CHECK_EQ(rounds, @R@);
                   CHECK_EQ(tx, @TX@);

                   auto clean = ex8_9::go_back_n(10, 4, {}, rounds, tx);
                   CHECK_EQ(rounds, @R0@);
                   CHECK_EQ(tx, @TX0@);
               }
               """, LOG=", ".join(f'"{x}"' for x in log), R=rounds, TX=tx, R0=rounds0, TX0=tx0),
               fill(r"""
               One lost segment cost @EXTRA@ extra transmissions: segment 5 itself plus 6 and 7, which arrived fine but were
               discarded because they were out of order. That waste is exactly what selective repeat and TCP's out-of-order buffering
               avoid. The loss also costs a whole extra round (RTT) of delay, which no retransmission scheme can avoid.
               """, EXTRA=tx - tx0))

    # ------------------------------------------------------------------ 8.10 flow vs congestion control
    B.md(r"""
    ## 8.10 Flow control vs congestion control

    These two mechanisms are easy to confuse. Both limit how much a sender may have in flight, but they protect different things:

    | | **flow control** | **congestion control** |
    |---|---|---|
    | protects | the **receiver**'s buffer | the **network** (router queues) |
    | window | **rwnd**: advertised by the receiver in every segment's *window* field | **cwnd**: computed by the sender, never transmitted |
    | signal | "I have N bytes of free buffer space" | loss (or delay/ECN marks) implies queues are overflowing |

    The sender may have at most $\min(\text{rwnd}, \text{cwnd})$ unacknowledged bytes in flight.
    The window field is 16 bits (max 65 535 bytes), too small for large BDPs, so a **window scale**
    option in the SYN multiplies it by $2^k$.
    """)
    B.question("concept", r"""Which mechanism limits throughput in each case? (a) A server streams to an old phone whose app reads
    data slowly, over an idle network. (b) A fast desktop downloads over a shared, congested ISP link.""",
               r"""
               (a) **Flow control**: the phone's receive buffer fills, it advertises a small (even zero) **rwnd**, and the
               sender must pause however empty the network is. (b) **Congestion control**: the receiver has plenty of buffer,
               but router queues overflow, losses occur, and the sender's **cwnd** shrinks. *Misconception:* "the window in the
               TCP header is the congestion window". The header carries only rwnd; cwnd lives inside the sender.
               """)

    # ------------------------------------------------------------------ 8.11 congestion control
    trace = cwnd_py(20, 16, {9}, {15})
    B.md(r"""
    ## 8.11 Congestion control: slow start and AIMD

    The classic TCP algorithm (Reno) adjusts **cwnd**, measured here in segments (MSS units), once per RTT:

    * **Slow start**: cwnd starts small and **doubles** every RTT (+1 per ACK) until it reaches the
      threshold **ssthresh**. Exponential growth finds the available capacity quickly.
    * **Congestion avoidance**: above ssthresh, grow **additively**: +1 segment per RTT.
    * **Loss detected by 3 duplicate ACKs** (mild): ssthresh = cwnd/2 and cwnd = ssthresh, a
      **multiplicative decrease** (*fast recovery*).
    * **Loss detected by a timeout** (severe, nothing is getting through): ssthresh = cwnd/2 and
      cwnd = 1, back to slow start.

    Additive increase plus multiplicative decrease = **AIMD**, which produces TCP's sawtooth.
    (Modern Linux defaults to CUBIC, which grows faster at high rates, but the structure is the same.)
    """)
    B.exercise("8.11", "Trace cwnd per RTT",
               fill(r"""
               `cwnd_trace(rtts, ssthresh, dupack_rtts, timeout_rtts)`: start with cwnd = 1. For each RTT `r = 0 … rtts−1`:
               **record** cwnd, then update it:
               * if `r` is in `dupack_rtts`: ssthresh = max(cwnd/2, 2); cwnd = ssthresh;
               * else if `r` is in `timeout_rtts`: ssthresh = max(cwnd/2, 2); cwnd = 1;
               * else if cwnd < ssthresh: cwnd = min(2·cwnd, ssthresh);
               * else cwnd += 1.

               (Integer division.) With ssthresh 16, a duplicate-ACK loss in RTT 9 and a timeout in RTT 15, the
               expected trace is `@T@`.
               """, T=", ".join(map(str, trace))),
               r"""
               namespace ex8_11 {
               std::vector<int> cwnd_trace(int rtts, int ssthresh, const std::set<int>& dupack_rtts,
                                           const std::set<int>& timeout_rtts) {
                   // TODO
                   return {};
               }
               }
               """,
               r"""
               namespace ex8_11 {
               std::vector<int> cwnd_trace(int rtts, int ssthresh, const std::set<int>& dupack_rtts,
                                           const std::set<int>& timeout_rtts) {
                   std::vector<int> out;
                   int cwnd = 1;
                   for (int r = 0; r < rtts; ++r) {
                       out.push_back(cwnd);
                       if (dupack_rtts.count(r)) {            // mild loss: halve (multiplicative decrease)
                           ssthresh = std::max(cwnd / 2, 2);
                           cwnd = ssthresh;
                       } else if (timeout_rtts.count(r)) {    // severe loss: restart slow start
                           ssthresh = std::max(cwnd / 2, 2);
                           cwnd = 1;
                       } else if (cwnd < ssthresh) {          // slow start: double
                           cwnd = std::min(2 * cwnd, ssthresh);
                       } else {                               // congestion avoidance: +1
                           cwnd += 1;
                       }
                   }
                   return out;
               }
               }
               """,
               fill(r"""
               {
                   auto t = ex8_11::cwnd_trace(20, 16, {9}, {15});
                   for (size_t r = 0; r < t.size(); ++r)
                       std::cout << "RTT " << std::setw(2) << r << " | " << std::string(size_t(std::max(t[r], 0)), '#')
                                 << " " << t[r] << "\n";
                   CHECK_EQ(t, (std::vector<int>{@T@}));
                   CHECK_EQ(ex8_11::cwnd_trace(6, 64, {}, {}), (std::vector<int>{@T2@}));   // pure slow start
               }
               """, T=", ".join(map(str, trace)), T2=", ".join(map(str, cwnd_py(6, 64, set(), set())))),
               r"""
               The chart shows the three regimes: exponential growth up to ssthresh (RTT 0–4), linear growth, halving at the
               duplicate-ACK loss, linear growth again, then the collapse to 1 after the timeout, followed by a fresh slow start up to
               the new, lower ssthresh. "Slow" start is actually the *fast* phase; the name contrasts it with the older behaviour of
               sending a full window at once.
               """)
    B.question("why", r"""Why does TCP increase additively but decrease multiplicatively? What would go wrong with multiplicative increase
    in congestion avoidance?""",
               r"""
               AIMD makes competing flows **converge to a fair share**: when two flows both halve, the larger one loses more in
               absolute terms, while additive increase adds the same amount to both; repeated cycles shrink the gap (Chiu & Jain's
               result). Multiplicative decrease also backs off fast enough to drain overflowing queues. With multiplicative
               *increase* above ssthresh, flows would overshoot capacity by large factors, causing bursts of heavy loss and never
               converging to fairness. Slow start is multiplicative only while far below the last known safe rate.
               """)

    # ------------------------------------------------------------------ 8.12 trade-offs
    B.md(r"""
    ## 8.12 UDP vs TCP: choosing

    | | UDP | TCP |
    |---|---|---|
    | connection setup | none (the first datagram carries data) | 1 RTT handshake before data |
    | delivery | unreliable, unordered, message boundaries kept | reliable, ordered byte stream |
    | congestion / flow control | none (the application's job) | built in |
    | head-of-line blocking | no | yes |
    | header | 8 bytes | 20–60 bytes |

    **Head-of-line blocking**: because TCP delivers bytes in order, one lost segment stalls delivery
    of all later bytes, even if they already arrived, until the retransmission fills the gap.
    """)
    B.question("concept", r"""Pick UDP or TCP, with a one-line reason each: (a) a DNS lookup, (b) a video call, (c) downloading a
    software update, (d) a multiplayer game sending player positions 60 times per second.""",
               r"""
               (a) **UDP**: one small question and one small answer; a handshake would double the latency; if lost, simply retry.
               (b) **UDP**: late audio is useless; a retransmitted frame would arrive after it should have been played, and
               head-of-line blocking would freeze the call.
               (c) **TCP**: every byte must arrive intact and in order; latency hardly matters.
               (d) **UDP**: each update supersedes the previous one; a lost position should be skipped, not retransmitted.
               *Misconception:* "UDP is faster". It is not faster on the wire; it simply lets the application skip reliability
               it does not need.
               """)
    B.recap(
        ["Ports multiplex programs; TCP connections are demultiplexed by the full 5-tuple, UDP by (dst IP, dst port).",
         "UDP header: 8 bytes (ports, length, checksum). UDP/TCP checksums cover a pseudo-header with the IP addresses.",
         "TCP numbers bytes: seq = first byte, ack = next byte expected (cumulative); SYN and FIN consume one number each.",
         "Handshake SYN → SYN|ACK → ACK; teardown FIN/ACK per direction; the active closer waits in TIME_WAIT for 2×MSL.",
         "Reliability = ACK + timeout + retransmit; windows fill the BDP. rwnd (flow control) protects the receiver, cwnd (slow start, AIMD) the network."],
        ["how a segment finds its socket, and why one server port serves many clients;",
         "every field of the TCP header, and how to decode the flags byte;",
         "why the handshake has three messages, and why TIME_WAIT exists;",
         "the difference between flow control and congestion control;",
         "a cwnd trace through slow start, AIMD, and a timeout."])
