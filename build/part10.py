import ipaddress

from nb import (fill, cpp_bytes, hexdump_py, eth_header, ipv4_header, tcp_segment, inet_checksum,
                tcp_flags_str)

CLIENT_MAC, GW_MAC = "3c:22:fb:12:ab:9e", "f0:9f:c2:10:20:30"
CLIENT_IP, SERVER_IP = "192.168.1.10", "203.0.113.80"
SPORT, DPORT, ISN, SERVER_ISN = 51514, 80, 0x9A3B27C1, 0x1F2E3D4C
MSS_OPT = bytes([2, 4, 0x05, 0xB4])     # MSS 1460


def pad60(b: bytes) -> bytes:
    return b + bytes(max(0, 60 - len(b)))


def syn_frame():
    tcp = tcp_segment(CLIENT_IP, SERVER_IP, SPORT, DPORT, ISN, 0, 0x02, 64240, options=MSS_OPT)
    ip = ipv4_header(CLIENT_IP, SERVER_IP, 6, len(tcp), ttl=64, ident=0x4D2A, df=True)
    return pad60(eth_header(GW_MAC, CLIENT_MAC, 0x0800) + ip + tcp), tcp, ip


def synack_frame():
    tcp = tcp_segment(SERVER_IP, CLIENT_IP, DPORT, SPORT, SERVER_ISN, ISN + 1, 0x12, 65160, options=MSS_OPT)
    ip = ipv4_header(SERVER_IP, CLIENT_IP, 6, len(tcp), ttl=64, ident=0, df=True)
    return pad60(eth_header(CLIENT_MAC, GW_MAC, 0x0800) + ip + tcp)


def build(B):
    B.part("10", "Capstone: dissect a real frame")
    frame, tcp, ip = syn_frame()
    reply = synack_frame()
    B.md(r"""
    # Part 10 — Capstone: dissect a real frame

    Below is a complete frame as a capture tool would show it (no preamble, no FCS): a laptop opening
    a TCP connection to a web server. It is Ethernet + IPv4 + a TCP **SYN** with an MSS option, and
    Ethernet padding up to the 60-byte minimum. Every length and checksum in it is valid.
    """)
    B.code(fill(r"""
    namespace capstone {
    const std::vector<uint8_t> syn_frame = {
    @B@
    };
    }
    """, B=cpp_bytes(frame, indent="    ")), tags=["data"])
    B.code(r"""
    hexdump(capstone::syn_frame);
    """)
    B.md(r"""
    ```
    offset  0 ─ 13   Ethernet header (dst, src, EtherType)
           14 ─ 33   IPv4 header (IHL = 5)
           34 ─ 57   TCP header (data offset = 6: 20 bytes + 4 bytes of options)
           58 ─ 59   Ethernet padding (IP's total length says the packet ends at 57)
    ```
    Every earlier helper you need is provided in one library cell:
    """)
    B.provided("lib10", [("1.2", "to_hex8"), ("1.4", "get_field"), ("1.6", "be"), ("5.2", "format_mac"),
                         ("5.4", "parse_eth"), ("6.1", "ipv4_text"), ("6.6", "parse_ipv4_header"),
                         ("6.7", "checksum"), ("8.3", "transport_checksum"), ("8.5", "parse_tcp")],
               unqualify=True)

    # ------------------------------------------------------------------ 10.1 MSS option walker
    B.md(r"""
    ## 10.1 Walking TCP options

    TCP options (bytes 20 … header_len − 1 of the TCP header) form a list of **TLV** (type-length-value) items:

    ```
    kind 0            end of option list (1 byte, stop)
    kind 1            NOP, no operation (1 byte, used as padding for alignment)
    any other kind    [kind][len][len − 2 bytes of data]      len counts kind and len themselves
    kind 2 = MSS      [02][04][16-bit MSS, big-endian]
    ```
    """)
    B.exercise("10.1", "Find the MSS option",
               r"""
               `find_mss(opts, n)`: walk the options; return the MSS value, or `-1` if absent or malformed (a length < 2 or one
               that runs past `n`).
               """,
               r"""
               namespace ex10_1 {
               int find_mss(const uint8_t* opts, size_t n) {
                   // TODO
                   return -1;
               }
               }
               """,
               r"""
               namespace ex10_1 {
               int find_mss(const uint8_t* opts, size_t n) {
                   size_t i = 0;
                   while (i < n) {
                       uint8_t kind = opts[i];
                       if (kind == 0) break;                 // end of list
                       if (kind == 1) { ++i; continue; }     // NOP
                       if (i + 1 >= n) return -1;            // no room for the length byte
                       uint8_t len = opts[i + 1];
                       if (len < 2 || i + len > n) return -1;   // malformed: would loop forever or overrun
                       if (kind == 2 && len == 4) return lib10::read_be16(opts + i + 2);
                       i += len;                             // skip any other option
                   }
                   return -1;
               }
               }
               """,
               r"""
               {
                   const uint8_t a[] = {0x02, 0x04, 0x05, 0xb4};
                   const uint8_t b[] = {0x01, 0x01, 0x04, 0x02, 0x02, 0x04, 0x02, 0x18};   // NOP NOP SACK-OK MSS 536
                   const uint8_t c[] = {0x01, 0x03, 0x03, 0x07, 0x00, 0x00, 0x00, 0x00};   // NOP, window scale 7, end
                   const uint8_t bad[] = {0x05, 0x00, 0x02, 0x04};                          // length 0: malformed
                   CHECK_EQ(ex10_1::find_mss(a, sizeof a), 1460);
                   CHECK_EQ(ex10_1::find_mss(b, sizeof b), 536);
                   CHECK_EQ(ex10_1::find_mss(c, sizeof c), -1);
                   CHECK_EQ(ex10_1::find_mss(bad, sizeof bad), -1);
               }
               """,
               r"""
               The `len < 2` check is essential: an option with length 0 would make `i += len` loop forever. That is a real
               denial-of-service bug class in packet parsers. Every TLV walker needs both checks, "the length makes progress" and
               "the length stays inside the buffer".
               """, snippet_key="find_mss")

    # ------------------------------------------------------------------ 10.2 dissector
    ip_hdr = ip
    tl = len(ip) + len(tcp)
    summary = "\n".join([
        f"Ethernet  {CLIENT_MAC} -> {GW_MAC}  type 0x0800",
        f"IPv4      {CLIENT_IP} -> {SERVER_IP}  ttl 64  proto 6  hdr 20  total {tl}  checksum OK",
        f"TCP       {SPORT} -> {DPORT}  seq {ISN}  flags {tcp_flags_str(0x02)}  hdr {len(tcp)}  mss 1460  checksum OK",
        f"padding   {len(frame) - 14 - tl} bytes"]).replace("\n", "\n               ")
    B.provided("lib10b", [("10.1", "find_mss")])
    B.exercise("10.2", "A three-layer dissector",
               r"""
               Fill in `dissect(frame)`, layer by layer, and **print** a summary like the one below. Return `std::nullopt` if any
               layer fails to parse, or if the EtherType is not IPv4 or the IP protocol is not TCP.

               * Ethernet: `lib10::parse_eth`; the IP packet starts at offset 14.
               * IPv4: `lib10::parse_ipv4_header`; `ip_checksum_ok` = the header checksums to 0 (`lib10::internet_checksum`).
                 The TCP segment spans `total_len − header_len` bytes after the IP header, and everything after the IP packet is
                 Ethernet padding.
               * TCP: `lib10::parse_tcp`; `tcp_checksum_ok` = `lib10::transport_checksum(...)` over the whole segment is 0; the MSS
                 comes from `lib10b::find_mss` on the option bytes.

               ```
               @SUMMARY@
               ```
               """.replace("@SUMMARY@", summary),
               r"""
               namespace ex10_2 {
               struct Dissection {
                   std::string eth_src, eth_dst;
                   uint16_t ethertype = 0;
                   std::string ip_src, ip_dst;
                   int ttl = 0, protocol = 0;
                   size_t ip_header_len = 0, ip_total_len = 0;
                   bool ip_checksum_ok = false;
                   uint16_t src_port = 0, dst_port = 0;
                   uint32_t seq = 0;
                   std::string flags;
                   size_t tcp_header_len = 0;
                   int mss = -1;
                   bool tcp_checksum_ok = false;
                   size_t eth_padding = 0;
               };
               std::optional<Dissection> dissect(const std::vector<uint8_t>& f) {
                   // TODO
                   return std::nullopt;
               }
               }
               """,
               r"""
               namespace ex10_2 {
               struct Dissection {
                   std::string eth_src, eth_dst;
                   uint16_t ethertype = 0;
                   std::string ip_src, ip_dst;
                   int ttl = 0, protocol = 0;
                   size_t ip_header_len = 0, ip_total_len = 0;
                   bool ip_checksum_ok = false;
                   uint16_t src_port = 0, dst_port = 0;
                   uint32_t seq = 0;
                   std::string flags;
                   size_t tcp_header_len = 0;
                   int mss = -1;
                   bool tcp_checksum_ok = false;
                   size_t eth_padding = 0;
               };
               std::optional<Dissection> dissect(const std::vector<uint8_t>& f) {
                   Dissection d;
                   // ---- L2: Ethernet ----
                   auto eth = lib10::parse_eth(f.data(), f.size());
                   if (!eth || eth->ethertype != 0x0800) return std::nullopt;
                   d.eth_src = lib10::format_mac(eth->src.data());
                   d.eth_dst = lib10::format_mac(eth->dst.data());
                   d.ethertype = eth->ethertype;

                   // ---- L3: IPv4 ----
                   const uint8_t* ipp = f.data() + 14;
                   size_t ip_avail = f.size() - 14;
                   auto ip = lib10::parse_ipv4_header(ipp, ip_avail);
                   if (!ip || ip->protocol != 6) return std::nullopt;
                   d.ip_src = lib10::format_ipv4(ip->src);
                   d.ip_dst = lib10::format_ipv4(ip->dst);
                   d.ttl = ip->ttl;
                   d.protocol = ip->protocol;
                   d.ip_header_len = ip->header_len();
                   d.ip_total_len = ip->total_len;
                   d.ip_checksum_ok = lib10::internet_checksum(ipp, d.ip_header_len) == 0;
                   d.eth_padding = ip_avail - d.ip_total_len;          // bytes beyond the IP packet

                   // ---- L4: TCP ----
                   const uint8_t* tp = ipp + d.ip_header_len;
                   size_t seg_len = d.ip_total_len - d.ip_header_len;  // trust IP's length, not the frame size
                   auto tcp = lib10::parse_tcp(tp, seg_len);
                   if (!tcp) return std::nullopt;
                   d.src_port = tcp->src_port;
                   d.dst_port = tcp->dst_port;
                   d.seq = tcp->seq;
                   d.flags = lib10::flags_to_string(tcp->flags);
                   d.tcp_header_len = tcp->header_len();
                   d.mss = lib10b::find_mss(tp + 20, d.tcp_header_len - 20);
                   d.tcp_checksum_ok = lib10::transport_checksum(ip->src, ip->dst, 6, tp, seg_len) == 0;

                   // ---- print a summary ----
                   std::cout << "Ethernet  " << d.eth_src << " -> " << d.eth_dst << "  type 0x" << std::hex
                             << std::setw(4) << std::setfill('0') << d.ethertype << std::dec << std::setfill(' ') << "\n"
                             << "IPv4      " << d.ip_src << " -> " << d.ip_dst << "  ttl " << d.ttl << "  proto "
                             << d.protocol << "  hdr " << d.ip_header_len << "  total " << d.ip_total_len
                             << "  checksum " << (d.ip_checksum_ok ? "OK" : "BAD") << "\n"
                             << "TCP       " << d.src_port << " -> " << d.dst_port << "  seq " << d.seq << "  flags "
                             << d.flags << "  hdr " << d.tcp_header_len << "  mss " << d.mss
                             << "  checksum " << (d.tcp_checksum_ok ? "OK" : "BAD") << "\n"
                             << "padding   " << d.eth_padding << " bytes\n";
                   return d;
               }
               }
               """,
               fill(r"""
               {
                   auto r = ex10_2::dissect(capstone::syn_frame);
                   CHECK(r.has_value());
                   auto d = r.value_or(ex10_2::Dissection{});
                   CHECK_EQ(d.eth_src, "@SM@");
                   CHECK_EQ(d.eth_dst, "@DM@");
                   CHECK_EQ(d.ethertype, 0x0800);
                   CHECK_EQ(d.ip_src, "@SI@");
                   CHECK_EQ(d.ip_dst, "@DI@");
                   CHECK_EQ(d.ttl, 64);
                   CHECK_EQ(d.protocol, 6);
                   CHECK_EQ(d.ip_header_len, 20u);
                   CHECK_EQ(d.ip_total_len, @TL@u);
                   CHECK(d.ip_checksum_ok);
                   CHECK_EQ(d.src_port, @SP@);
                   CHECK_EQ(d.dst_port, @DP@);
                   CHECK_EQ(d.seq, @SEQ@u);
                   CHECK_EQ(d.flags, "@FL@");
                   CHECK_EQ(d.tcp_header_len, 24u);
                   CHECK_EQ(d.mss, 1460);
                   CHECK(d.tcp_checksum_ok);
                   CHECK_EQ(d.eth_padding, @PAD@u);

                   std::cout << "\n-- the same frame with one TTL bit flipped in transit --\n";
                   auto bad = capstone::syn_frame;
                   bad[14 + 8] ^= 0x01;
                   auto rb = ex10_2::dissect(bad).value_or(ex10_2::Dissection{});
                   CHECK(!rb.ip_checksum_ok);
                   CHECK(rb.tcp_checksum_ok);     // the TCP checksum does not cover TTL

                   std::cout << "\n-- the same frame with the destination port corrupted --\n";
                   auto bad2 = capstone::syn_frame;
                   bad2[14 + 20 + 3] ^= 0x10;
                   auto rb2 = ex10_2::dissect(bad2).value_or(ex10_2::Dissection{});
                   CHECK(rb2.ip_checksum_ok);
                   CHECK(!rb2.tcp_checksum_ok);
               }
               """, SM=CLIENT_MAC, DM=GW_MAC, SI=CLIENT_IP, DI=SERVER_IP, TL=len(ip_hdr) + len(tcp), SP=SPORT, DP=DPORT,
                    SEQ=ISN, FL=tcp_flags_str(0x02), PAD=len(frame) - 14 - len(ip_hdr) - len(tcp)),
               r"""
               The key design point is **which length to trust at each layer**. Ethernet delivered 60 bytes, but IP's total length
               (44) defines the packet, so the 2 trailing bytes are padding, and the TCP segment length comes from IP, not from the
               frame. The corruption tests show each checksum's coverage: TTL is covered by the IP header checksum only; ports are
               covered by the TCP checksum only. On a real link the Ethernet CRC would have caught both, but a router's memory
               corruption after the CRC check would not have been caught by it.
               """, snippet_key="dissect")

    # ------------------------------------------------------------------ 10.3 build the SYN-ACK
    B.provided("lib10c", [("10.2", "dissect")])
    B.exercise("10.3", "Build the server's SYN|ACK reply, byte by byte",
               fill(r"""
               Now write bytes instead of reading them. `build_syn_ack(syn, server_isn)` returns the reply frame:

               * **Ethernet**: swap the MAC addresses; EtherType 0x0800.
               * **IPv4**: `0x45`, TOS 0, total length 44, identification 0, flags DF (bytes 6–7 = `0x4000`), TTL 64, protocol 6,
                 checksum computed last, source/destination = the SYN's destination/source.
               * **TCP**: ports swapped; seq = `server_isn`; ack = SYN's seq + 1; data offset 6; flags SYN|ACK (0x12);
                 window 65160; urgent 0; options = MSS 1460 (`02 04 05 b4`); checksum computed over the pseudo-header + segment.
               * Pad the frame with zeros to 60 bytes.

               Fill every checksum field with 0 before computing it. For `server_isn = 0x@ISN@` the correct frame is:
               ```
               @D@
               ```
               """, ISN=f"{SERVER_ISN:08X}", D=hexdump_py(reply)),
               r"""
               namespace ex10_3 {
               std::vector<uint8_t> build_syn_ack(const std::vector<uint8_t>& syn, uint32_t server_isn) {
                   // TODO (lib10::write_be16/write_be32/read_be16/read_be32, internet_checksum, transport_checksum)
                   return {};
               }
               }
               """,
               r"""
               namespace ex10_3 {
               std::vector<uint8_t> build_syn_ack(const std::vector<uint8_t>& syn, uint32_t server_isn) {
                   if (syn.size() < 14 + 20 + 20) return {};
                   std::vector<uint8_t> f(14 + 20 + 24, 0);                   // Ethernet + IPv4 + TCP with MSS
                   // ---- Ethernet: swap addresses ----
                   std::memcpy(&f[0], &syn[6], 6);                             // dst = SYN's source
                   std::memcpy(&f[6], &syn[0], 6);                             // src = SYN's destination
                   lib10::write_be16(&f[12], 0x0800);

                   // ---- IPv4 ----
                   const uint8_t* sip = &syn[14];
                   size_t syn_ihl = size_t(sip[0] & 0x0F) * 4;
                   uint8_t* ip = &f[14];
                   ip[0] = 0x45;                                               // version 4, IHL 5
                   lib10::write_be16(ip + 2, 20 + 24);                         // total length
                   lib10::write_be16(ip + 6, 0x4000);                          // DF
                   ip[8] = 64;                                                 // TTL
                   ip[9] = 6;                                                  // TCP
                   std::memcpy(ip + 12, sip + 16, 4);                          // src = SYN's dst
                   std::memcpy(ip + 16, sip + 12, 4);                          // dst = SYN's src
                   lib10::write_be16(ip + 10, lib10::internet_checksum(ip, 20));

                   // ---- TCP ----
                   const uint8_t* st = sip + syn_ihl;
                   uint8_t* t = ip + 20;
                   lib10::write_be16(t + 0, lib10::read_be16(st + 2));         // src port = SYN's dst port
                   lib10::write_be16(t + 2, lib10::read_be16(st + 0));         // dst port = SYN's src port
                   lib10::write_be32(t + 4, server_isn);
                   lib10::write_be32(t + 8, lib10::read_be32(st + 4) + 1);     // ack = client ISN + 1
                   t[12] = 6 << 4;                                             // data offset 6
                   t[13] = 0x12;                                               // SYN|ACK
                   lib10::write_be16(t + 14, 65160);                           // window
                   const uint8_t mss[4] = {0x02, 0x04, 0x05, 0xb4};
                   std::memcpy(t + 20, mss, 4);
                   uint32_t src = lib10::read_be32(ip + 12), dst = lib10::read_be32(ip + 16);
                   lib10::write_be16(t + 16, lib10::transport_checksum(src, dst, 6, t, 24));

                   f.resize(60, 0);                                            // Ethernet minimum (without FCS)
                   return f;
               }
               }
               """,
               fill(r"""
               {
                   auto reply = ex10_3::build_syn_ack(capstone::syn_frame, 0x@ISN@u);
                   hexdump(reply);
                   CHECK_EQ(reply, (std::vector<uint8_t>{
               @B@
                   }));
                   std::cout << "\n-- dissecting your reply --\n";
                   auto d = lib10c::dissect(reply).value_or(lib10c::Dissection{});
                   CHECK(d.ip_checksum_ok && d.tcp_checksum_ok);
                   CHECK_EQ(d.flags, "@FL@");
               }
               """, ISN=f"{SERVER_ISN:08X}", B=cpp_bytes(reply, indent="        "), FL=tcp_flags_str(0x12)),
               r"""
               Building a packet is parsing in reverse, with one ordering constraint: **checksums last**, each computed while its
               own field is still zero. The TCP checksum depends on the IP addresses (pseudo-header), but the IP checksum does not
               depend on TCP, so either header may be finished first. Kernels do exactly this, and most NICs can compute the
               checksums in hardware ("checksum offload"). That is why captures taken on the sending host sometimes show
               "incorrect" checksums.
               """)

    # ------------------------------------------------------------------ 10.4 full trace
    B.md(r"""
    ## 10.4 The whole journey

    You can now follow a request through every layer and every device.
    """)
    B.question("concept", r"""Trace one HTTP request (`GET /` from a laptop on home Wi-Fi to a web server on the Internet) **down** the 7
    layers on the laptop, **across** the network, and **up** the 7 layers on the server. At each step, name the device(s)
    that touch that layer.""",
               r"""
               **Down, on the laptop**
               * **L7 Application**: the browser forms `GET / HTTP/1.1` + headers.
               * **L6 Presentation**: text encoding (ASCII/UTF-8) and optional compression, done inside the browser.
               * **L5 Session**: connection reuse (keep-alive) and cookies, managed by the browser's HTTP library.
               * **L4 Transport**: the kernel's TCP puts the bytes into segments (ports 51514 → 80, seq/ack, checksum with
                 pseudo-header), after the 3-way handshake.
               * **L3 Network**: the kernel's IP adds src 192.168.1.10 and the server's IP as dst, TTL 64, header checksum;
                 longest-prefix match picks the default route → next hop = gateway.
               * **L2 Data link**: ARP cache → gateway MAC; the NIC driver/NIC builds the 802.11/Ethernet frame (dst = gateway
                 MAC) and appends the CRC.
               * **L1 Physical**: the NIC's PHY transmits radio symbols.

               **Across the network**
               * **AP** (L1–L2): radio → Ethernet bridging. **Switch** in the home box (L1–L2): forwards by dst MAC to the router port.
               * **Home router** (L1–L3, and L4 for NAT): strips L2, LPM → ISP default route, TTL−1, checksum update,
                 **NAT rewrites the source IP and port** (and patches the TCP checksum), then a new L2 header for the WAN link.
               * **Modem/ONT** (L1–L2): modulates the frame onto DSL/coax/fibre.
               * **ISP and Internet routers** (L1–L3): at each hop, CRC check, LPM, TTL−1, checksum update, new L2 header.
               * **Switches in the server's data centre** (L1–L2).

               **Up, on the server**
               * **L1/L2**: the NIC checks the CRC, filters by MAC, and DMAs the frame into the RX ring.
               * **L3**: the kernel checks the IP checksum and that the destination is its own address; protocol 6 → TCP.
               * **L4**: TCP verifies the checksum, demultiplexes by 5-tuple to the connected socket, ACKs, and delivers bytes in order.
               * **L5–L7**: the web server reads from the socket, frames the HTTP request (by `\r\n\r\n` and `Content-Length`),
                 parses it, and produces the response, which travels the same path in reverse (NAT translating the destination
                 back to the laptop).

               *Key insight:* L2 headers are rebuilt at **every** hop, L3 addresses stay end-to-end (except where NAT rewrites
               them), and L4 and above are touched only by the two endpoints (and NAT).
               """)

    # ------------------------------------------------------------------ 10.5 final quiz
    B.md(r"""
    ## 10.5 Final quiz

    Ten quick questions spanning the whole notebook. Answer each before expanding its solution.
    """)
    import ipaddress as _ip
    n22 = _ip.ip_network("10.0.5.20/22", strict=False)
    same = _ip.IPv4Address("10.0.6.1") in n22
    B.question("concept", r"""A switch forwards what PDU, based on which header field?""",
               r"""A **frame** (L2), based on the **destination MAC address** (and it learns from the source MAC).""")
    B.question("compute", r"""How many usable host addresses does a /26 have?""",
               f"""$2^{{32-26}} - 2$ = **{2**6 - 2}**: the network and broadcast addresses are not usable.""")
    B.question("predict", r"""On x86, what does `std::cout << htons(0x0050);` print (decimal)?""",
               f"""**{0x5000}** (0x5000): the two bytes are swapped on a little-endian host. 0x0050 is port 80.""")
    B.question("concept", r"""List everything a router changes in an IPv4 packet it forwards (no NAT).""",
               r"""**TTL** (−1) and therefore the **header checksum**, plus a completely **new L2 header** (source = its own
               outgoing MAC, destination = next hop's MAC, new CRC). IP addresses, ports and payload are unchanged (it might
               fragment if DF is clear and the packet exceeds the MTU).""")
    B.question("compute", fill(r"""Host `10.0.5.20/22` sends to `10.0.6.1`. Direct delivery or via the gateway?""", ),
               f"""The /22 network is **{n22.network_address}–{n22.broadcast_address}**, so 10.0.6.1 is
               **{'inside it: direct delivery' if same else 'outside it: via the gateway'}**. The host ARPs for 10.0.6.1 itself.""")
    B.question("compute", r"""How long does it take to transmit a 1500-byte frame onto a 100 Mb/s link?""",
               f"""$L/R = 12000 / 10^8$ = **{12000/1e8*1e6:g} µs**. That is the transmission delay; propagation delay is additional.""")
    B.question("concept", r"""Does a router forward an ARP request? Why or why not?""",
               r"""**No.** ARP requests are L2 broadcasts, and broadcasts stay within the LAN; a router works at L3 and does not
               forward L2 broadcasts. ARP only ever resolves addresses on the local link.""")
    B.question("concept", r"""Which TCP window travels in the header, and what does it protect?""",
               r"""**rwnd**, the receive window (flow control). It protects the **receiver's buffer**. cwnd (congestion control)
               is private to the sender and protects the network.""")
    B.question("concept", r"""After a TCP connection closes normally, which side sits in `TIME_WAIT`, and for how long?""",
               r"""The side that sent the **first FIN** (the active closer), for **2 × MSL** (60 s on Linux), so that it can re-ACK a
               retransmitted FIN and so that stale segments die before the 5-tuple is reused.""")
    B.question("concept", r"""`connect()` fails with `ECONNREFUSED`. What arrived from the network?""",
               r"""A TCP **RST** in reply to the SYN: the host is reachable but nothing listens on that port. (A silent drop would
               have given `ETIMEDOUT` instead.)""")
    B.md(r"""
    ## Final score

    Run the next cell to see how many checks you have passed. (Re-running a test cell counts its checks again;
    restart the kernel and *Run All* for a clean count.)
    """)
    B.code(r"""
    print_score();
    """)
    B.recap(
        ["A real frame is parsed layer by layer, each layer's length field bounding the next.",
         "Each checksum covers a specific range: the IP header only; TCP = pseudo-header + segment; Ethernet CRC = whole frame.",
         "TLV option walkers must check both 'makes progress' and 'stays in bounds'.",
         "Building packets is parsing in reverse, with checksums computed last over zeroed fields.",
         "L2 is rebuilt per hop, L3 is end-to-end (except NAT), and L4+ belongs to the endpoints."],
        ["every byte of an Ethernet + IPv4 + TCP SYN frame;",
         "which checksum catches which corruption, and why padding is not part of the IP packet;",
         "how a server constructs its SYN|ACK from the client's SYN;",
         "the full path of an HTTP request through all layers and all devices."])
