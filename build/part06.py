import ipaddress

from nb import fill, cpp_bytes, hexdump_py, ipv4_header, inet_checksum, ip2int, ones_sum16


def net(s):
    return ipaddress.ip_network(s, strict=False)


ROUTES = [("0.0.0.0", 0, "isp"), ("10.0.0.0", 8, "core"), ("10.1.0.0", 16, "campus"),
          ("10.1.2.0", 24, "lab"), ("10.1.2.128", 25, "lab-b"), ("192.168.1.0", 24, "direct")]
LPM_QUERIES = ["10.1.2.200", "10.1.2.5", "10.1.3.4", "10.9.9.9", "8.8.8.8", "192.168.1.77"]


def lpm_py(dst, routes=ROUTES):
    best = None
    for p, l, nh in routes:
        if ipaddress.IPv4Address(dst) in net(f"{p}/{l}"):
            if best is None or l > best[0]:
                best = (l, nh)
    return best[1] if best else None


def arp_sim():
    lan = {"192.168.1.1": "aa:aa:aa:00:00:01", "192.168.1.50": "aa:aa:aa:00:00:50"}
    cache, ttl, reqs = {}, 60.0, 0
    script = [(0.0, "192.168.1.1"), (10.0, "192.168.1.1"), (30.0, "192.168.1.50"),
              (70.0, "192.168.1.1"), (71.0, "192.168.1.99"), (72.0, "192.168.1.99")]
    results = []
    for now, ip in script:
        e = cache.get(ip)
        if e and now < e[1]:
            results.append((e[0], reqs))
            continue
        cache.pop(ip, None)
        reqs += 1
        if ip in lan:
            cache[ip] = (lan[ip], now + ttl)
            results.append((lan[ip], reqs))
        else:
            results.append((None, reqs))
    return lan, script, results


def traceroute_py(routers, dest, max_ttl):
    out = []
    for ttl in range(1, max_ttl + 1):
        if ttl <= len(routers):
            out.append(f"{ttl} {routers[ttl - 1]}")
        else:
            out.append(f"{ttl} {dest}")
            break
    return out


def build(B):
    B.part("6", "Network layer: IPv4")
    B.md(r"""
    # Part 6 — Network layer: IPv4

    Ethernet delivers frames within one LAN. **IP** (Internet Protocol) delivers **packets** between
    hosts anywhere, across many networks connected by routers. This part covers IPv4, version 4,
    which still carries most Internet traffic.
    """)

    # ------------------------------------------------------------------ 6.1
    B.md(r"""
    ## 6.1 IPv4 addresses: dotted decimal ↔ `uint32_t`

    An IPv4 address is 32 bits, written as four decimal **octets** (bytes) separated by dots:

    ```
    192   .  168   .    1   .   10
    0xC0     0xA8      0x01     0x0A     ->  as one number: 0xC0A8010A = 3232235786
    ```

    In this notebook an address is a `uint32_t` **value** whose most significant byte is the
    first octet. On the wire the same address is 4 big-endian bytes, so `read_be32` converts one
    into the other. The POSIX function `inet_pton(AF_INET, text, &addr)` also parses text; it stores
    the address in a `struct in_addr` whose field `s_addr` is in **network byte order**.
    """)
    B.exercise("6.1", "Parse and format dotted-decimal",
               r"""
               * `parse_ipv4(s)`: return the address, or `std::nullopt` unless `s` is exactly four octets of 1–3 digits, each
                 ≤ 255, separated by single dots (no spaces, no signs). Loop over the characters, keeping the current octet
                 value, the number of digits in it, and the number of dots seen.
               * `format_ipv4(ip)`: the inverse (`std::to_string` converts a number to text).
               """,
               r"""
               namespace ex6_1 {
               std::optional<uint32_t> parse_ipv4(const std::string& s) {
                   // TODO
                   return std::nullopt;
               }
               std::string format_ipv4(uint32_t ip) {
                   // TODO
                   return "";
               }
               }
               """,
               r"""
               namespace ex6_1 {
               std::optional<uint32_t> parse_ipv4(const std::string& s) {
                   uint32_t result = 0, octet = 0;
                   int dots = 0, digits = 0;
                   for (char c : s) {
                       if (c >= '0' && c <= '9') {
                           octet = octet * 10 + uint32_t(c - '0');
                           if (++digits > 3 || octet > 255) return std::nullopt;
                       } else if (c == '.') {
                           if (digits == 0 || dots == 3) return std::nullopt;   // empty octet / too many dots
                           result = (result << 8) | octet;                     // shift in the finished octet
                           ++dots; octet = 0; digits = 0;
                       } else {
                           return std::nullopt;                                // any other character
                       }
                   }
                   if (dots != 3 || digits == 0) return std::nullopt;
                   return (result << 8) | octet;
               }
               std::string format_ipv4(uint32_t ip) {
                   return std::to_string(ip >> 24) + "." + std::to_string((ip >> 16) & 0xFF) + "." +
                          std::to_string((ip >> 8) & 0xFF) + "." + std::to_string(ip & 0xFF);
               }
               }
               """,
               fill(r"""
               {
                   CHECK_EQ(ex6_1::parse_ipv4("192.168.1.10").value_or(0), @A@u);
                   CHECK_EQ(ex6_1::parse_ipv4("10.0.0.1").value_or(0), @B@u);
                   CHECK_EQ(ex6_1::parse_ipv4("255.255.255.255").value_or(0), 0xFFFFFFFFu);
                   CHECK(ex6_1::parse_ipv4("0.0.0.0").has_value());
                   for (const char* bad : {"256.1.1.1", "1.2.3", "1.2.3.4.5", "a.b.c.d", "1..2.3", "", "1.2.3.", "1234.1.1.1"})
                       CHECK(!ex6_1::parse_ipv4(bad).has_value());
                   CHECK_EQ(ex6_1::format_ipv4(@A@u), "192.168.1.10");
                   CHECK_EQ(ex6_1::format_ipv4(0), "0.0.0.0");

                   in_addr a{};                                   // cross-check against the C library
                   inet_pton(AF_INET, "172.20.3.4", &a);
                   CHECK_EQ(ex6_1::parse_ipv4("172.20.3.4").value_or(0), ntohl(a.s_addr));
               }
               """, A=ip2int("192.168.1.10"), B=ip2int("10.0.0.1")),
               r"""
               The parser builds the number the same way `read_be32` does, shifting each finished octet in from the right. The
               validation cases are exactly the ones real parsers get wrong; `"1.2.3.4.5"` and `"1..2.3"` have caused security bugs
               in allow-lists. Comparing with `inet_pton` needs `ntohl`, because `s_addr` holds the bytes in network order.
               """, snippet_key="ipv4_text")

    # ------------------------------------------------------------------ 6.2
    n1 = net("10.1.2.3/20")
    B.md(r"""
    ## 6.2 Subnets, masks and CIDR

    A **subnet** is a block of consecutive addresses that share their top $n$ bits, the
    **prefix**. The notation `10.1.2.3/20` (**CIDR**, classless inter-domain routing) means "the
    first 20 bits identify the network; the remaining 12 identify the host".
    The **subnet mask** has the top $n$ bits set: `/20` → `255.255.240.0`.

    ```
    address    10.1.2.3       00001010.00000001.0000|0010.00000011
    mask /20   255.255.240.0  11111111.11111111.1111|0000.00000000
    network    ip & mask      00001010.00000001.0000|0000.00000000  = 10.1.0.0
    broadcast  net | ~mask    00001010.00000001.0000|1111.11111111  = 10.1.15.255
    ```

    The all-zeros host part names the **network** and the all-ones host part is the subnet's
    **broadcast** address, so a /n subnet has $2^{32-n} - 2$ usable host addresses. (Exceptions: a /31
    has 2 usable addresses for point-to-point links, and a /32 is one single host.)
    """)
    q = net("172.16.45.200/22")
    B.question("compute", r"""For `172.16.45.200/22`: what are the mask, network address, broadcast address and number of usable hosts?""",
               f"""
               Mask **{q.netmask}**, network **{q.network_address}**, broadcast **{q.broadcast_address}**, usable hosts
               $2^{{10}} - 2$ = **{q.num_addresses - 2}**.

               Shortcut: /22 leaves 2 host bits in the third octet, so the network's third octet is a multiple of 4:
               45 → 44, and the block spans 44–47. The common mistake is to "round" 45 to 40 or 32 by eye.
               """)
    B.provided("lib6", [("1.6", "be"), ("6.1", "ipv4_text")])
    B.exercise("6.2", "Masks, network, broadcast, host count",
               r"""
               Implement the four functions. `prefix_to_mask(0)` must be `0`; remember the `<< 32` trap from §1.1.
               """,
               r"""
               namespace ex6_2 {
               uint32_t prefix_to_mask(int n)              { return 0; }   // TODO
               uint32_t network_addr(uint32_t ip, int n)   { return 0; }   // TODO
               uint32_t broadcast_addr(uint32_t ip, int n) { return 0; }   // TODO
               uint64_t host_count(int n)                  { return 0; }   // TODO (/31 -> 2, /32 -> 1)
               }
               """,
               r"""
               namespace ex6_2 {
               uint32_t prefix_to_mask(int n) {
                   if (n <= 0) return 0;                       // shifting by 32 would be undefined behaviour
                   return 0xFFFFFFFFu << (32 - n);             // n ones followed by 32-n zeros
               }
               uint32_t network_addr(uint32_t ip, int n)   { return ip & prefix_to_mask(n); }
               uint32_t broadcast_addr(uint32_t ip, int n) { return network_addr(ip, n) | ~prefix_to_mask(n); }
               uint64_t host_count(int n) {
                   if (n == 32) return 1;
                   if (n == 31) return 2;
                   return (uint64_t(1) << (32 - n)) - 2;       // 64-bit: 1 << 32 is fine for /0
               }
               }
               """,
               fill(r"""
               {
                   auto ip = [](const char* s) { return lib6::parse_ipv4(s).value_or(0); };
                   CHECK_EQ(lib6::format_ipv4(ex6_2::prefix_to_mask(20)), "@M20@");
                   CHECK_EQ(ex6_2::prefix_to_mask(0), 0u);
                   CHECK_EQ(ex6_2::prefix_to_mask(32), 0xFFFFFFFFu);
                   CHECK_EQ(lib6::format_ipv4(ex6_2::network_addr(ip("10.1.2.3"), 20)), "@N1@");
                   CHECK_EQ(lib6::format_ipv4(ex6_2::broadcast_addr(ip("10.1.2.3"), 20)), "@B1@");
                   CHECK_EQ(lib6::format_ipv4(ex6_2::network_addr(ip("172.16.45.200"), 22)), "@N2@");
                   CHECK_EQ(lib6::format_ipv4(ex6_2::broadcast_addr(ip("192.168.1.130"), 25)), "@B3@");
                   CHECK_EQ(ex6_2::host_count(24), @H24@u);
                   CHECK_EQ(ex6_2::host_count(20), @H20@u);
                   CHECK_EQ(ex6_2::host_count(31), 2u);
                   CHECK_EQ(ex6_2::host_count(0), @H0@ull);
               }
               """, M20=net("0.0.0.0/20").netmask, N1=n1.network_address, B1=n1.broadcast_address,
                    N2=q.network_address, B3=net("192.168.1.130/25").broadcast_address,
                    H24=2 ** 8 - 2, H20=2 ** 12 - 2, H0=2 ** 32 - 2),
               r"""
               `~prefix_to_mask(n)` is the *host mask* (the low 32−n bits set), so OR-ing it onto the network address sets
               every host bit. `host_count` uses 64-bit arithmetic because a /0 has 2³² addresses, which does not fit in 32 bits.
               """, snippet_key="masks")

    # ------------------------------------------------------------------ 6.3
    B.md(r"""
    ## 6.3 Deliver directly, or send to the default gateway

    Every host is configured with an address, a prefix length, and a **default gateway**: the IP
    address of a router on its own subnet. To send a packet to `dst`, a host decides:

    ```
    if network(dst, n) == network(my_ip, n):   deliver directly: dst is on my LAN
    else:                                      hand the packet to the default gateway
    ```

    Either way the packet travels inside an Ethernet frame addressed to the MAC of the chosen
    **next hop**, which is `dst` itself or the gateway. The IP header always keeps the *final* destination.
    """)
    B.provided("lib6b", [("6.2", "masks")])
    B.exercise("6.3", "Same subnet? Next hop?",
               r"""
               * `in_same_subnet(a, b, n)`
               * `next_hop(my_ip, n, dst, gateway)`: returns the IP address whose MAC the frame must be sent to.
               """,
               r"""
               namespace ex6_3 {
               bool in_same_subnet(uint32_t a, uint32_t b, int n) { return false; }                     // TODO
               uint32_t next_hop(uint32_t my_ip, int n, uint32_t dst, uint32_t gateway) { return 0; }   // TODO
               }
               """,
               r"""
               namespace ex6_3 {
               bool in_same_subnet(uint32_t a, uint32_t b, int n) {
                   return lib6b::network_addr(a, n) == lib6b::network_addr(b, n);
               }
               uint32_t next_hop(uint32_t my_ip, int n, uint32_t dst, uint32_t gateway) {
                   return in_same_subnet(my_ip, dst, n) ? dst : gateway;
               }
               }
               """,
               r"""
               {
                   auto ip = [](const char* s) { return lib6::parse_ipv4(s).value_or(0); };
                   uint32_t me = ip("192.168.1.10"), gw = ip("192.168.1.1");
                   CHECK(ex6_3::in_same_subnet(me, ip("192.168.1.200"), 24));
                   CHECK(!ex6_3::in_same_subnet(me, ip("192.168.2.5"), 24));
                   CHECK(ex6_3::in_same_subnet(me, ip("192.168.2.5"), 16));          // the mask decides!
                   CHECK_EQ(lib6::format_ipv4(ex6_3::next_hop(me, 24, ip("192.168.1.77"), gw)), "192.168.1.77");
                   CHECK_EQ(lib6::format_ipv4(ex6_3::next_hop(me, 24, ip("203.0.113.9"), gw)), "192.168.1.1");
               }
               """,
               r"""
               The whole decision is one comparison of network addresses. Note the third check: the *same* pair of
               addresses is local under /16 but remote under /24. A mistyped prefix length therefore makes a host send
               local traffic to the router, or ARP for remote hosts that never answer.
               """)
    B.question("concept", r"""Host 192.168.1.10/24 sends a packet to 93.184.216.34. In the Ethernet frame that leaves the laptop,
    whose MAC address is the destination, and whose IP address is the IP destination?""",
               r"""
               The **Ethernet** destination is the **gateway's MAC** (the next hop on this link); the **IP** destination is
               **93.184.216.34** (the final destination). L2 addresses change at every hop, while L3 addresses stay end-to-end.
               (NAT in Part 7 is the notable exception that rewrites IP addresses.) This is the single most important
               idea connecting Parts 5 and 6.
               """)

    # ------------------------------------------------------------------ 6.4
    lpm_ans = [lpm_py(d) for d in LPM_QUERIES]
    B.md(r"""
    ## 6.4 Routing tables and longest-prefix match

    A router (and every host) has a **routing table** of entries *prefix/len → next hop*. The
    entry `0.0.0.0/0` matches every address: it is the **default route**. A destination can match
    several entries, and the rule is **longest-prefix match** (LPM): use the most specific one.

    ```
    prefix/len        next hop          dst 10.1.2.200 matches?
    0.0.0.0/0         isp               yes (len 0)
    10.0.0.0/8        core              yes (len 8)
    10.1.0.0/16       campus            yes (len 16)
    10.1.2.0/24       lab               yes (len 24)
    10.1.2.128/25     lab-b             yes (len 25)   <- longest: wins
    ```

    Routers fill these tables using **routing protocols** (e.g. OSPF inside one organisation and BGP
    between ISPs); their internals are beyond this notebook.
    """)
    B.exercise("6.4", "Longest-prefix match",
               r"""
               `lpm(table, dst)` returns the next hop of the longest matching entry, or `std::nullopt` if nothing
               matches. The result must not depend on the order of the table.
               """,
               r"""
               namespace ex6_4 {
               struct Route { uint32_t prefix; int len; std::string next_hop; };
               std::optional<std::string> lpm(const std::vector<Route>& table, uint32_t dst) {
                   // TODO (use lib6b::network_addr)
                   return std::nullopt;
               }
               }
               """,
               r"""
               namespace ex6_4 {
               struct Route { uint32_t prefix; int len; std::string next_hop; };
               std::optional<std::string> lpm(const std::vector<Route>& table, uint32_t dst) {
                   int best_len = -1;
                   std::string best;
                   for (const auto& r : table) {
                       bool match = lib6b::network_addr(dst, r.len) == r.prefix;   // dst inside prefix/len?
                       if (match && r.len > best_len) { best_len = r.len; best = r.next_hop; }
                   }
                   if (best_len < 0) return std::nullopt;
                   return best;
               }
               }
               """,
               fill(r"""
               {
                   auto ip = [](const char* s) { return lib6::parse_ipv4(s).value_or(0); };
                   std::vector<ex6_4::Route> table = {
               @ROUTES@
                   };
                   std::vector<std::string> dsts = {@Q@};
                   std::vector<std::string> want = {@A@};
                   for (size_t i = 0; i < dsts.size(); ++i)
                       CHECK_EQ(ex6_4::lpm(table, ip(dsts[i].c_str())).value_or("<none>"), want[i]);

                   std::reverse(table.begin(), table.end());                 // order must not matter
                   CHECK_EQ(ex6_4::lpm(table, ip("10.1.2.200")).value_or("<none>"), "@A0@");

                   std::vector<ex6_4::Route> no_default = {{ip("10.0.0.0"), 8, "core"}};
                   CHECK(!ex6_4::lpm(no_default, ip("8.8.8.8")).has_value());   // no route: packet dropped
               }
               """, ROUTES="\n".join(f'        {{ip("{p}"), {l}, "{nh}"}},' for p, l, nh in ROUTES),
                    Q=", ".join(f'"{d}"' for d in LPM_QUERIES), A=", ".join(f'"{a}"' for a in lpm_ans), A0=lpm_ans[0]),
               r"""
               A linear scan is the clearest correct algorithm. Real routers hold about a million Internet prefixes and must decide
               in nanoseconds, so they use tries (prefix trees) or special memory (TCAM) that compares all entries in parallel.
               The semantics, longest match wins, are identical. A packet that matches no entry is dropped, and the router may send
               the source an error message saying the destination is unreachable.
               """)
    B.question("predict", r"""With the table above, where do packets to `10.1.2.127` and `10.1.2.128` go?""",
               f"""
               `10.1.2.127` → **{lpm_py('10.1.2.127')}**, and `10.1.2.128` → **{lpm_py('10.1.2.128')}**. The /25 covers only
               .128–.255, so .127 falls back to the /24. Boundary addresses are where hand-computed LPM goes wrong: write the
               last octet in binary (`0111 1111` vs `1000 0000`) and compare the 25th bit.
               """)

    # ------------------------------------------------------------------ 6.5 ARP
    B.md(r"""
    ## 6.5 ARP: from an IP next hop to a MAC address

    §6.3 gives the next hop's **IP** address, but the NIC can only send frames to a **MAC**
    address. **ARP** (Address Resolution Protocol) bridges L3 → L2 on a LAN:

    ```
    192.168.1.10                                       192.168.1.1 (gateway)
         |-- ARP request, dst MAC ff:ff:ff:ff:ff:ff -->|  "Who has 192.168.1.1? Tell 192.168.1.10"
         |   (broadcast: every host on the LAN hears)  |   every other host ignores it
         |<-- ARP reply, dst MAC = requester's MAC ----|  "192.168.1.1 is at aa:aa:aa:00:00:01"
    ```

    The answer is stored in an **ARP cache** (IP → MAC) for a limited time (tens of seconds to
    minutes) so that not every packet needs a lookup. ARP messages ride directly in Ethernet
    frames with EtherType `0x0806`. The frame you parsed in §5.4 **was** an ARP request:
    """)
    B.code(r"""
    hexdump(frames5::arp_frame);
    """)
    B.md(r"""
    ```
    ARP payload (starts at frame offset 14)
    offset  size  field                    value in the frame above
    0       2     hardware type            0x0001 = Ethernet
    2       2     protocol type            0x0800 = IPv4
    4       1     hardware address length  6
    5       1     protocol address length  4
    6       2     operation                1 = request, 2 = reply
    8       6     sender MAC               3c:22:fb:12:ab:9e
    14      4     sender IP                192.168.1.10
    18      6     target MAC               00:00:00:00:00:00  (unknown: that is the question)
    24      4     target IP                192.168.1.1
    ```
    """)
    B.provided("lib6c", [("5.2", "format_mac")])
    B.exercise("6.5a", "Decode the ARP message",
               r"""
               Fill in `parse_arp(p, n)`, where `p` points at the ARP payload (frame offset 14). Return `std::nullopt` if
               `n < 28` or if the hardware/protocol type and lengths are not Ethernet/IPv4 (1, 0x0800, 6, 4).
               """,
               r"""
               namespace ex6_5a {
               struct Arp {
                   uint16_t op = 0;
                   std::string sender_mac, target_mac;
                   uint32_t sender_ip = 0, target_ip = 0;
               };
               std::optional<Arp> parse_arp(const uint8_t* p, size_t n) {
                   // TODO (lib6::read_be16/read_be32, lib6c::format_mac)
                   return std::nullopt;
               }
               }
               """,
               r"""
               namespace ex6_5a {
               struct Arp {
                   uint16_t op = 0;
                   std::string sender_mac, target_mac;
                   uint32_t sender_ip = 0, target_ip = 0;
               };
               std::optional<Arp> parse_arp(const uint8_t* p, size_t n) {
                   if (n < 28) return std::nullopt;
                   if (lib6::read_be16(p) != 1 || lib6::read_be16(p + 2) != 0x0800 || p[4] != 6 || p[5] != 4)
                       return std::nullopt;                        // not Ethernet/IPv4 ARP
                   Arp a;
                   a.op         = lib6::read_be16(p + 6);
                   a.sender_mac = lib6c::format_mac(p + 8);
                   a.sender_ip  = lib6::read_be32(p + 14);
                   a.target_mac = lib6c::format_mac(p + 18);
                   a.target_ip  = lib6::read_be32(p + 24);
                   return a;
               }
               }
               """,
               r"""
               {
                   const auto& f = frames5::arp_frame;
                   auto a = ex6_5a::parse_arp(f.data() + 14, f.size() - 14).value_or(ex6_5a::Arp{});
                   CHECK_EQ(a.op, 1);
                   CHECK_EQ(a.sender_mac, "3c:22:fb:12:ab:9e");
                   CHECK_EQ(lib6::format_ipv4(a.sender_ip), "192.168.1.10");
                   CHECK_EQ(a.target_mac, "00:00:00:00:00:00");
                   CHECK_EQ(lib6::format_ipv4(a.target_ip), "192.168.1.1");
                   CHECK(!ex6_5a::parse_arp(f.data() + 14, 20).has_value());
                   std::cout << "Who has " << lib6::format_ipv4(a.target_ip) << "? Tell "
                             << lib6::format_ipv4(a.sender_ip) << "\n";
               }
               """,
               r"""
               Every field sits at a fixed offset, so parsing is the same pattern as for Ethernet: check the length, then read at
               offsets with the big-endian helpers. Checking the type and length fields up front rejects ARP for other
               hardware or protocols instead of misreading it.
               """)
    lan, script, results = arp_sim()
    B.exercise("6.5b", "Simulate an ARP cache",
               r"""
               Implement `resolve(ip, now)`:
               1. If the cache holds `ip` and `now < expires`: return the cached MAC (**hit**).
               2. Otherwise (absent or expired): erase any stale entry, increment `requests_sent`, and print
                  `ARP request: who has <ip>?`. If `lan` contains `ip`, print `ARP reply: <ip> is at <mac>`, cache it with
                  `expires = now + ttl`, and return the MAC. If not, return `std::nullopt` (nobody answered).

               `lan` stands in for the other hosts on the LAN: the map of who would answer. `m.count(k)` returns 1 if a
               key is present, and `m.erase(k)` removes it.
               """,
               r"""
               namespace ex6_5b {
               struct ArpCache {
                   struct Entry { std::string mac; double expires; };
                   std::map<uint32_t, Entry> cache;
                   std::map<uint32_t, std::string> lan;   // who answers ARP on this LAN (simulation input)
                   double ttl = 60.0;
                   int requests_sent = 0;

                   std::optional<std::string> resolve(uint32_t ip, double now) {
                       // TODO
                       return std::nullopt;
                   }
               };
               }
               """,
               r"""
               namespace ex6_5b {
               struct ArpCache {
                   struct Entry { std::string mac; double expires; };
                   std::map<uint32_t, Entry> cache;
                   std::map<uint32_t, std::string> lan;   // who answers ARP on this LAN (simulation input)
                   double ttl = 60.0;
                   int requests_sent = 0;

                   std::optional<std::string> resolve(uint32_t ip, double now) {
                       auto it = cache.find(ip);
                       if (it != cache.end() && now < it->second.expires) return it->second.mac;   // hit
                       cache.erase(ip);                                         // expired (or absent)
                       ++requests_sent;
                       std::cout << "  ARP request: who has " << lib6::format_ipv4(ip) << "?\n";   // broadcast
                       if (!lan.count(ip)) return std::nullopt;                 // nobody answered
                       const std::string& mac = lan.at(ip);
                       std::cout << "  ARP reply: " << lib6::format_ipv4(ip) << " is at " << mac << "\n";  // unicast
                       cache[ip] = Entry{mac, now + ttl};
                       return mac;
                   }
               };
               }
               """,
               fill(r"""
               {
                   auto ip = [](const char* s) { return lib6::parse_ipv4(s).value_or(0); };
                   ex6_5b::ArpCache host;
               @LAN@
                   struct Step { double t; const char* ip; const char* want_mac; int want_requests; };
                   std::vector<Step> steps = {
               @STEPS@
                   };
                   for (const auto& s : steps) {
                       std::cout << "t=" << s.t << "s resolve " << s.ip << "\n";
                       auto mac = host.resolve(ip(s.ip), s.t);
                       CHECK_EQ(mac.value_or("<no reply>"), s.want_mac);
                       CHECK_EQ(host.requests_sent, s.want_requests);
                   }
               }
               """, LAN="\n".join(f'    host.lan[ip("{k}")] = "{v}";' for k, v in lan.items()),
                    STEPS="\n".join(f'        {{{t}, "{i}", "{m or "<no reply>"}", {r}}},'
                                    for (t, i), (m, r) in zip(script, results))),
               r"""
               The trace shows the cache at work: the second lookup of the gateway (t=10) costs nothing; at t=70 the entry is
               60 s old and has expired, so it is re-requested. Entries expire because the IP → MAC binding can change (a new
               device takes over the address, or a NIC is replaced). The unknown host triggers a request **every** time, which is
               why real stacks rate-limit ARP and briefly remember failures.
               """)
    B.question("concept", r"""Your laptop (192.168.1.10/24) opens a web page on 93.184.216.34. Does it send an ARP request for
    93.184.216.34? Explain.""",
               r"""
               **No.** ARP only works within the LAN: a broadcast never crosses a router, and the web server is not on this
               link. By §6.3 the next hop is the **gateway**, so the laptop ARPs for **192.168.1.1**, and only if that entry is
               not already cached. The router then does its own ARP (or equivalent) on the next link. *Misconception:* "ARP
               finds the MAC of the destination host". It finds the MAC of the **next hop**.
               """)
    B.question("why", r"""Why is the ARP request broadcast but the reply unicast? What does that imply about trusting ARP replies?""",
               r"""
               The requester does not yet know **which** host owns the IP, so it must ask everyone; the replier knows exactly who
               asked, because the request carries the sender's MAC and IP, so it answers only that host. ARP has **no
               authentication**: any host can send a forged reply ("192.168.1.1 is at *my* MAC") and hosts will usually cache it.
               This is *ARP spoofing*, a classic way to intercept LAN traffic.
               """)

    # ------------------------------------------------------------------ 6.6 IPv4 header
    hdr = ipv4_header("192.168.1.10", "203.0.113.7", 17, 32, ttl=64, ident=0x1c46, df=True)
    pkt = hdr + bytes(range(32))
    opts = ipv4_header("10.0.0.1", "10.0.0.2", 6, 20, ttl=1, ident=0xabcd, df=False, options=bytes([1, 1, 1, 0]))
    pkt_opts = opts + bytes(20)
    B.md(r"""
    ## 6.6 The IPv4 header

    ```
    byte  0          1          2          3
       +----------+----------+----------+----------+
     0 |ver | IHL | DSCP/ECN |     total length    |   ver = 4; IHL = header length in 32-bit words (5..15)
       +----------+----------+----------+----------+
     4 |   identification    |flg| fragment offset |   flags (3 bits): DF = don't fragment, MF = more fragments
       +----------+----------+----------+----------+
     8 |   TTL    | protocol |   header checksum   |   protocol: 1 = ICMP, 6 = TCP, 17 = UDP
       +----------+----------+----------+----------+
    12 |               source address              |
       +----------+----------+----------+----------+
    16 |            destination address            |
       +----------+----------+----------+----------+
    20 |    options (only if IHL > 5) ...          |
    ```

    * **total length** = header + payload in bytes (so an IP packet is at most 65 535 bytes).
    * **TTL** (time to live): decremented by each router (§6.8).
    * **protocol** names the payload: this is IP's demultiplexing field.
    * **DSCP/ECN** mark priority and congestion; identification, flags and fragment offset serve
      fragmentation (§6.9).
    """)
    B.code(fill(r"""
    namespace frames6 {
    // UDP-carrying packet: 20-byte header + 32 payload bytes
    const std::vector<uint8_t> ip_pkt = {
    @P@
    };
    // TCP-carrying packet with 4 bytes of options (IHL = 6) + 20 payload bytes
    const std::vector<uint8_t> ip_opts = {
    @O@
    };
    }
    """, P=cpp_bytes(pkt, indent="    "), O=cpp_bytes(pkt_opts, indent="    ")), tags=["data"])
    B.code(r"""
    hexdump(frames6::ip_pkt);
    """)
    B.question("compute", r"""A header begins `46 00 02 00`. What are the version, header length in bytes, total length, and payload length?""",
               f"""
               0x46 → version = **4**, IHL = 6 → header = 6 × 4 = **24 bytes** (it has 4 bytes of options).
               Total length = 0x0200 = **{0x0200}** bytes → payload = {0x0200} − 24 = **{0x0200 - 24} bytes**.

               *Misconception:* IHL counts **32-bit words**, not bytes. Reading IHL = 6 as 6 bytes is the classic parser bug.
               """)
    B.provided("lib6d", [("1.4", "get_field")])
    B.exercise("6.6", "Parse an IPv4 header",
               r"""
               Fill in `parse_ipv4_header(p, n)`. Return `std::nullopt` unless: `n ≥ 20`, version is 4, IHL ≥ 5,
               the header fits (`IHL*4 ≤ n`), and `IHL*4 ≤ total_len ≤ n`. The flags are the top 3 bits of byte 6;
               the fragment offset is the low 13 bits of bytes 6–7.
               """,
               r"""
               namespace ex6_6 {
               struct Ipv4Header {
                   uint8_t version = 0, ihl = 0, ttl = 0, protocol = 0, flags = 0;
                   uint16_t total_len = 0, ident = 0, frag_offset = 0, checksum = 0;
                   uint32_t src = 0, dst = 0;
                   size_t header_len() const { return size_t(ihl) * 4; }
               };
               std::optional<Ipv4Header> parse_ipv4_header(const uint8_t* p, size_t n) {
                   // TODO
                   return std::nullopt;
               }
               }
               """,
               r"""
               namespace ex6_6 {
               struct Ipv4Header {
                   uint8_t version = 0, ihl = 0, ttl = 0, protocol = 0, flags = 0;
                   uint16_t total_len = 0, ident = 0, frag_offset = 0, checksum = 0;
                   uint32_t src = 0, dst = 0;
                   size_t header_len() const { return size_t(ihl) * 4; }
               };
               std::optional<Ipv4Header> parse_ipv4_header(const uint8_t* p, size_t n) {
                   if (n < 20) return std::nullopt;
                   Ipv4Header h;
                   h.version     = lib6d::get_field(p[0], 4, 4);     // high nibble
                   h.ihl         = lib6d::get_field(p[0], 0, 4);     // low nibble, in 32-bit words
                   h.total_len   = lib6::read_be16(p + 2);
                   h.ident       = lib6::read_be16(p + 4);
                   h.flags       = lib6d::get_field(p[6], 5, 3);     // top 3 bits of byte 6
                   h.frag_offset = lib6::read_be16(p + 6) & 0x1FFF;  // low 13 bits
                   h.ttl         = p[8];
                   h.protocol    = p[9];
                   h.checksum    = lib6::read_be16(p + 10);
                   h.src         = lib6::read_be32(p + 12);
                   h.dst         = lib6::read_be32(p + 16);
                   if (h.version != 4 || h.ihl < 5) return std::nullopt;
                   if (h.header_len() > n || h.total_len < h.header_len() || h.total_len > n) return std::nullopt;
                   return h;
               }
               }
               """,
               fill(r"""
               {
                   const auto& pk = frames6::ip_pkt;
                   auto h = ex6_6::parse_ipv4_header(pk.data(), pk.size()).value_or(ex6_6::Ipv4Header{});
                   CHECK_EQ(h.version, 4);
                   CHECK_EQ(h.header_len(), 20u);
                   CHECK_EQ(h.total_len, @TL@);
                   CHECK_EQ(h.ident, 0x1c46);
                   CHECK_EQ(h.flags, 0x2);               // DF set
                   CHECK_EQ(h.frag_offset, 0);
                   CHECK_EQ(h.ttl, 64);
                   CHECK_EQ(h.protocol, 17);             // UDP
                   CHECK_EQ(h.checksum, 0x@CS@);
                   CHECK_EQ(lib6::format_ipv4(h.src), "192.168.1.10");
                   CHECK_EQ(lib6::format_ipv4(h.dst), "203.0.113.7");

                   const auto& po = frames6::ip_opts;
                   auto h2 = ex6_6::parse_ipv4_header(po.data(), po.size()).value_or(ex6_6::Ipv4Header{});
                   CHECK_EQ(h2.header_len(), 24u);        // IHL = 6
                   CHECK_EQ(h2.protocol, 6);              // TCP
                   CHECK_EQ(h2.flags, 0);

                   CHECK(!ex6_6::parse_ipv4_header(pk.data(), 19).has_value());   // truncated
                   std::vector<uint8_t> v6 = pk;  v6[0] = 0x65;                   // version 6
                   CHECK(!ex6_6::parse_ipv4_header(v6.data(), v6.size()).has_value());
                   std::vector<uint8_t> small = pk;  small[0] = 0x44;             // IHL = 4: impossible
                   CHECK(!ex6_6::parse_ipv4_header(small.data(), small.size()).has_value());
               }
               """, TL=len(pkt), CS=f"{int.from_bytes(hdr[10:12], 'big'):04x}"),
               r"""
               Two details deserve attention. First, field extraction reuses §1.4: `get_field(p[0], 4, 4)` is the version. Second,
               the validation order: a real stack checks that the header **fits** before trusting IHL, and that `total_len` is
               consistent, because an attacker controls every byte. Trailing bytes beyond `total_len` (for example Ethernet padding)
               are allowed, which is why the check is `total_len ≤ n`, not `==`.
               """, snippet_key="parse_ipv4_header")

    # ------------------------------------------------------------------ 6.7 checksum
    w = [0xFFFF, 0x0002]
    raw = sum(w)
    folded = (raw & 0xFFFF) + (raw >> 16)
    hz = hdr[:10] + b"\x00\x00" + hdr[12:]
    odd = bytes([0x01, 0x02, 0x03])
    B.md(fill(r"""
    ## 6.7 The Internet checksum

    The header checksum protects the IPv4 header (not the payload) against corruption in routers'
    memory or on links. It is the **one's complement** of the **one's-complement sum** of all 16-bit
    big-endian words:

    1. Set the checksum field to 0 and add all 16-bit words in a wide (32-bit) accumulator.
    2. **Fold** the carries: while the sum exceeds 16 bits, `sum = (sum & 0xFFFF) + (sum >> 16)`.
       This *end-around carry* is what makes it one's-complement arithmetic. Example:
       `0xFFFF + 0x0002 = 0x@RAW@` → fold → `0x@FOLD@`.
    3. Complement: `checksum = ~sum` (16 bits). With an odd number of bytes, pad a zero byte at the end.

    **Verifying:** sum all words *including* the checksum and fold. A correct header gives
    `0xFFFF`, whose complement is `0`. So a receiver simply checks `internet_checksum(header) == 0`.
    """, RAW=f"{raw:05X}", FOLD=f"{folded:04X}"))
    B.exercise("6.7", "Compute and verify the Internet checksum",
               r"""
               * `internet_checksum(p, n)`: steps 1–3 over `n` bytes (handle odd `n`).
               * `ipv4_header_ok(p, n)`: `true` if the IPv4 header at `p` (length from IHL) checksums to 0.
                 Return `false` if the header does not fit in `n` bytes.
               """,
               r"""
               namespace ex6_7 {
               uint16_t internet_checksum(const uint8_t* p, size_t n) { return 0xFFFF; }   // TODO
               bool ipv4_header_ok(const uint8_t* p, size_t n)        { return false; }    // TODO
               }
               """,
               r"""
               namespace ex6_7 {
               uint16_t internet_checksum(const uint8_t* p, size_t n) {
                   uint32_t sum = 0;
                   for (size_t i = 0; i + 1 < n; i += 2)
                       sum += (uint32_t(p[i]) << 8) | p[i + 1];      // big-endian 16-bit words
                   if (n % 2) sum += uint32_t(p[n - 1]) << 8;       // odd length: pad with a zero byte
                   while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);   // end-around carry
                   return uint16_t(~sum);
               }
               bool ipv4_header_ok(const uint8_t* p, size_t n) {
                   if (n < 20) return false;
                   size_t hl = size_t(p[0] & 0x0F) * 4;
                   if (hl < 20 || hl > n) return false;
                   return internet_checksum(p, hl) == 0;             // includes the stored checksum
               }
               }
               """,
               fill(r"""
               {
                   const auto& pk = frames6::ip_pkt;
                   std::vector<uint8_t> h(pk.begin(), pk.begin() + 20);
                   h[10] = 0; h[11] = 0;                                        // sender's view: field zeroed
                   CHECK_EQ(ex6_7::internet_checksum(h.data(), h.size()), 0x@CS@);
                   CHECK(ex6_7::ipv4_header_ok(pk.data(), pk.size()));
                   CHECK(ex6_7::ipv4_header_ok(frames6::ip_opts.data(), frames6::ip_opts.size()));

                   const uint8_t odd[] = {0x01, 0x02, 0x03};
                   CHECK_EQ(ex6_7::internet_checksum(odd, 3), 0x@ODD@);

                   std::vector<uint8_t> bad = pk;
                   bad[8] = uint8_t(bad[8] - 1);                               // a router decremented TTL...
                   CHECK(!ex6_7::ipv4_header_ok(bad.data(), bad.size()));       // ...but forgot the checksum
               }
               """, CS=f"{inet_checksum(hz):04x}", ODD=f"{inet_checksum(odd):04x}"),
               r"""
               The 32-bit accumulator cannot overflow for any IP-sized input, and folding in a loop handles the case where the
               first fold itself produces a carry. Verifying by checksumming the *whole* header, stored checksum included, and
               expecting 0 is simpler and less error-prone than zeroing the field and comparing.
               """, snippet_key="checksum")
    B.question("why", r"""Every router must recompute the IPv4 header checksum for every packet it forwards. Why? And give one kind of
    corruption the Internet checksum cannot detect.""",
               r"""
               Each router **decrements TTL**, which changes the header, so the checksum must change too. Routers update it
               incrementally, without re-summing everything. Because addition is **commutative**, swapping two 16-bit words
               (e.g. corrupted memory that exchanges the source and destination addresses) leaves the sum unchanged and goes
               undetected. So do errors that cancel, such as +1 in one word and −1 in another. That is why links add a CRC as well.
               IPv6 dropped the header checksum entirely and relies on the link-layer and transport-layer checks.
               """)

    # ------------------------------------------------------------------ 6.8 TTL / ICMP / traceroute
    routers = ["home-gw", "isp-edge", "isp-core", "ix-peer"]
    tr5 = traceroute_py(routers, "server", 30)
    tr3 = traceroute_py(routers, "server", 3)
    B.md(r"""
    ## 6.8 TTL, ICMP, and traceroute

    If a routing mistake creates a **loop**, a packet could circle forever. So every router decrements
    the **TTL** field, and a packet whose TTL reaches 0 is **discarded**. The router then sends the
    source an **ICMP** *Time Exceeded* message.

    **ICMP** (Internet Control Message Protocol, IP protocol 1) carries network error and diagnostic
    messages inside IP packets. **Ping** sends ICMP *Echo Request* and times the *Echo Reply*.

    **Traceroute** exploits TTL: it sends probes with TTL = 1, 2, 3, …. The probe with TTL = *k* dies
    at the *k*-th router, whose Time Exceeded reply reveals that router's address. Once TTL is large
    enough, the probe reaches the destination, which replies normally.

    ```
    TTL=1:  me --> R1 (TTL 1->0: drop)  ==> R1 replies "Time Exceeded"
    TTL=2:  me --> R1 --> R2 (drop)     ==> R2 replies
    TTL=5:  me --> R1 --> R2 --> R3 --> R4 --> server  ==> server replies
    ```
    """)
    B.exercise("6.8", "Simulate traceroute",
               r"""
               `traceroute(routers, dest, max_ttl)`: for each TTL from 1 to `max_ttl`, determine who answers the probe and
               append `"<ttl> <name>"`. Stop after the destination answers.
               """,
               r"""
               namespace ex6_8 {
               std::vector<std::string> traceroute(const std::vector<std::string>& routers,
                                                   const std::string& dest, int max_ttl) {
                   // TODO
                   return {};
               }
               }
               """,
               r"""
               namespace ex6_8 {
               std::vector<std::string> traceroute(const std::vector<std::string>& routers,
                                                   const std::string& dest, int max_ttl) {
                   std::vector<std::string> out;
                   for (int ttl = 1; ttl <= max_ttl; ++ttl) {
                       if (ttl <= int(routers.size())) {
                           // the TTL hits 0 at router number ttl, which sends Time Exceeded
                           out.push_back(std::to_string(ttl) + " " + routers[ttl - 1]);
                       } else {
                           out.push_back(std::to_string(ttl) + " " + dest);   // reached the destination
                           break;
                       }
                   }
                   return out;
               }
               }
               """,
               fill(r"""
               {
                   std::vector<std::string> path = {@R@};
                   auto t = ex6_8::traceroute(path, "server", 30);
                   for (const auto& line : t) std::cout << line << "\n";
                   CHECK_EQ(t, (std::vector<std::string>{@T5@}));
                   CHECK_EQ(ex6_8::traceroute(path, "server", 3), (std::vector<std::string>{@T3@}));
               }
               """, R=", ".join(f'"{r}"' for r in routers), T5=", ".join(f'"{x}"' for x in tr5),
                    T3=", ".join(f'"{x}"' for x in tr3)),
               r"""
               The router at position *k* is exactly the one where a TTL-*k* probe expires. Real traceroute sends 3 probes per TTL
               and prints their round-trip times; routers that do not send ICMP show up as `* * *`. Because every probe is an
               independent packet, successive probes may take different paths.
               """)
    B.question("compute", r"""A packet arrives at your server with TTL = 57. The sender's OS starts packets at TTL 64. How many routers did it cross?
    If a routing loop between two routers forms, what happens to a packet with TTL = 64 that enters the loop?""",
               f"""
               64 − 57 = **{64-57} routers** (each decrements once). In the loop it bounces between the two routers, losing 1 per hop,
               until TTL hits 0 after at most 64 hops, and a Time Exceeded message goes back to the source. Without TTL, loops
               would fill links with immortal packets. *Misconception:* "TTL is a time in seconds". Originally it was meant as
               seconds, but in practice it is a **hop count**.
               """)

    # ------------------------------------------------------------------ 6.9 fragmentation
    data_len, mtu = 3980, 1500
    per = (mtu - 20) // 8 * 8
    frags = []
    off = 0
    while off < data_len:
        ln = min(per, data_len - off)
        frags.append((ln, off // 8, 1 if off + ln < data_len else 0))
        off += ln
    B.md(r"""
    ## 6.9 MTU and fragmentation (briefly)

    If a packet is larger than the **MTU** of the next link (1500 for Ethernet), an IPv4 router may
    **fragment** it: it splits the payload into pieces that each get a copy of the header, with the same
    *identification*, a *fragment offset* (in units of 8 bytes), and the **MF** (more fragments) flag
    on all but the last piece. Only the destination **reassembles** them, and losing any fragment loses the whole packet.

    If the **DF** (don't fragment) flag is set, the router drops the packet instead and returns an
    ICMP *Fragmentation Needed* message. Modern hosts set DF and use those messages to discover the
    path's smallest MTU (**path MTU discovery**), then send packets that fit.
    """)
    B.question("compute", r"""A 4000-byte IPv4 packet (20-byte header + 3980 bytes of data, DF clear) must cross a link with MTU 1500.
    List each fragment's data length, fragment-offset field value, and MF flag.""",
               "Each fragment carries at most 1500 − 20 = 1480 data bytes (a multiple of 8, as offsets require):\n\n"
               "| fragment | data bytes | offset field (×8 bytes) | MF |\n|---|---|---|---|\n"
               + "\n".join(f"| {i+1} | {ln} | {o} | {mf} |" for i, (ln, o, mf) in enumerate(frags))
               + f"\n\nThe offsets are {', '.join(str(o * 8) for _, o, _ in frags)} bytes, divided by 8. "
               "*Misconception:* forgetting that each fragment needs its own 20-byte header, and thus using 1500 data bytes per fragment.")
    B.md(r"""
    > **IPv6 in one table** (for comparison only)
    >
    > | | IPv4 | IPv6 |
    > |---|---|---|
    > | address size | 32 bits | 128 bits, written in hex, e.g. `2001:db8::1` |
    > | header | 20–60 bytes, with checksum | fixed 40 bytes, **no** checksum |
    > | fragmentation | by routers or source | by the source only |
    > | L3 → L2 resolution | ARP (broadcast) | Neighbor Discovery (multicast ICMPv6) |
    > | address shortage | yes → NAT (Part 7) | no: every device can have a public address |
    """)
    B.recap(
        ["IPv4 address = 32 bits; prefix/n splits it into network and host parts; network = ip & mask, broadcast = network | ~mask.",
         "Same subnet → deliver directly; otherwise → default gateway. The frame goes to the next hop's MAC; the IP destination is final.",
         "Routing = longest-prefix match over prefix/len entries; 0.0.0.0/0 is the default route.",
         "ARP maps a next-hop IP to a MAC: broadcast request, unicast reply, cached with a timeout, unauthenticated.",
         "IPv4 header: IHL in words, total length, TTL (hop count, drives traceroute via ICMP), protocol, one's-complement checksum."],
        ["how to compute network, broadcast and host count for any CIDR block;",
         "which MAC and which IP a packet to a remote server carries on the first link;",
         "why longest-prefix match picks the most specific route;",
         "every field of the IPv4 header and its offset;",
         "how traceroute discovers routers, and why routers must update the checksum."])
