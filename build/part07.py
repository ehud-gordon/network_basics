import ipaddress
import struct

from nb import fill, cpp_bytes, hexdump_py, ip2int

RANGES = [("10.0.0.0/8", "private"), ("172.16.0.0/12", "private"), ("192.168.0.0/16", "private"),
          ("127.0.0.0/8", "loopback"), ("169.254.0.0/16", "link-local"), ("100.64.0.0/10", "shared")]
CLASSIFY = ["10.20.30.40", "172.16.0.1", "172.31.255.254", "172.32.0.1", "192.168.1.10", "127.0.0.1",
            "169.254.12.34", "100.72.1.1", "8.8.8.8", "192.169.0.1"]


def classify_py(s):
    a = ipaddress.IPv4Address(s)
    for n, k in RANGES:
        if a in ipaddress.ip_network(n):
            return k
    return "public"


def dns_name(name: str) -> bytes:
    out = b""
    for label in name.rstrip(".").split("."):
        out += bytes([len(label)]) + label.encode()
    return out + b"\x00"


def dns_query(qid, name, qtype):
    return struct.pack("!HHHHHH", qid, 0x0100, 1, 0, 0, 0) + dns_name(name) + struct.pack("!HH", qtype, 1)


class DhcpPy:
    def __init__(self, lo, hi):
        self.lo, self.hi, self.leases = lo, hi, {}

    def owner(self, ip):
        return next((m for m, i in self.leases.items() if i == ip), None)

    def offer(self, mac):
        if mac in self.leases:
            return self.leases[mac]
        for ip in range(self.lo, self.hi + 1):
            if self.owner(ip) is None:
                return ip
        return None

    def request(self, mac, ip):
        if not (self.lo <= ip <= self.hi):
            return False
        o = self.owner(ip)
        if o is not None and o != mac:
            return False
        self.leases.pop(mac, None)
        self.leases[mac] = ip
        return True

    def release(self, mac):
        self.leases.pop(mac, None)


def build(B):
    B.part("7", "Home and ISP infrastructure services")
    B.md(r"""
    # Part 7 — Home and ISP infrastructure services

    Part 4 listed the functions inside a home "router" box. Now that you know IP, here is how
    each one works.

    ## 7.1 Private and public addresses

    IPv4 has only $2^{32} \approx 4.3$ billion addresses, far fewer than devices. **RFC 1918**
    therefore reserves three **private** ranges (an RFC, "request for comments", is an Internet standard document) that anyone may use inside their own network and
    that Internet routers **never** forward:

    | range | CIDR | typical use |
    |---|---|---|
    | 10.0.0.0 – 10.255.255.255 | 10.0.0.0/8 | companies, clouds |
    | 172.16.0.0 – 172.31.255.255 | 172.16.0.0/12 | companies, container networks |
    | 192.168.0.0 – 192.168.255.255 | 192.168.0.0/16 | home networks |

    Other special ranges: `127.0.0.0/8` **loopback** (packets never leave the host; `127.0.0.1` is
    "this machine"), `169.254.0.0/16` **link-local** (self-assigned when no DHCP server answers), and
    `100.64.0.0/10` **shared** space used by ISPs that NAT their customers. A **public** address is
    globally unique and routable on the Internet.
    """)
    B.provided("lib7", [("1.6", "be"), ("6.1", "ipv4_text"), ("6.2", "masks")])
    B.exercise("7.1", "Classify an address",
               r"""
               Return `"private"`, `"loopback"`, `"link-local"`, `"shared"` or `"public"`. A helper
               `in_block(ip, "a.b.c.d", n)` built from `lib7::network_addr` and `lib7::parse_ipv4` keeps it short.
               """,
               r"""
               namespace ex7_1 {
               std::string classify(uint32_t ip) {
                   // TODO
                   return "";
               }
               }
               """,
               r"""
               namespace ex7_1 {
               bool in_block(uint32_t ip, const char* net, int n) {
                   return lib7::network_addr(ip, n) == lib7::parse_ipv4(net).value_or(0);
               }
               std::string classify(uint32_t ip) {
                   if (in_block(ip, "10.0.0.0", 8) || in_block(ip, "172.16.0.0", 12) || in_block(ip, "192.168.0.0", 16))
                       return "private";
                   if (in_block(ip, "127.0.0.0", 8))    return "loopback";
                   if (in_block(ip, "169.254.0.0", 16)) return "link-local";
                   if (in_block(ip, "100.64.0.0", 10))  return "shared";
                   return "public";
               }
               }
               """,
               fill(r"""
               {
                   std::vector<std::string> ips  = {@IPS@};
                   std::vector<std::string> want = {@WANT@};
                   for (size_t i = 0; i < ips.size(); ++i) {
                       std::string got = ex7_1::classify(lib7::parse_ipv4(ips[i]).value_or(0));
                       std::cout << ips[i] << " -> " << got << "\n";
                       CHECK_EQ(got, want[i]);
                   }
               }
               """, IPS=", ".join(f'"{x}"' for x in CLASSIFY), WANT=", ".join(f'"{classify_py(x)}"' for x in CLASSIFY)),
               r"""
               Reusing `network_addr` makes each range test one line. The tricky cases are the boundaries of the /12:
               `172.31.255.254` is private while `172.32.0.1` is public, and `192.169.0.1` is public despite "looking like" a
               home address.
               """)
    B.question("concept", r"""A colleague says "172.32.10.5 is a private address, like 172.16.x.x". Right or wrong?""",
               r"""
               **Wrong.** `172.16.0.0/12` fixes the top 12 bits: 172 = `1010 1100`, then the high nibble of the second octet must
               be `0001`, so the second octet runs 16 (`0001 0000`) … 31 (`0001 1111`). 32 is `0010 0000` → outside. Only
               172.16–172.31 are private. This is a favourite interview trap.
               """)

    # ------------------------------------------------------------------ 7.2 NAT
    B.md(r"""
    ## 7.2 NAT and PAT

    Recall that a *port* is the 16-bit number (Part 3) identifying a program on a host; `IP:port`
    names one endpoint. Private addresses cannot appear on the Internet, so the home router performs
    **NAT** (network address translation), or more precisely **PAT** (port address translation). It
    rewrites every outgoing packet's source IP and port to its **one public IP** and a port it picks,
    and remembers the mapping:

    ```
    inside (private)                   NAT table                     outside (public)
    192.168.1.10:5555 ──► | 192.168.1.10:5555 <-> 203.0.113.5:50000 | ──► 203.0.113.5:50000 -> server:80
    192.168.1.11:5555 ──► | 192.168.1.11:5555 <-> 203.0.113.5:50001 | ──► 203.0.113.5:50001 -> server:80
    replies to 203.0.113.5:50001 ──► look up port 50001 ──► rewrite destination to 192.168.1.11:5555
    ```

    A reply whose destination port has **no** mapping is **dropped**. The router must also fix the
    IP header checksum, and also the transport-layer checksum, which covers the ports and (through a
    so-called pseudo-header, §8.3) the IP addresses as well.
    """)
    B.exercise("7.2", "Simulate a NAT",
               r"""
               * `outbound(p)`: look up `(p.src_ip, p.src_port)`; if absent, allocate `next_port++` and record the mapping
                 in both maps. Return the packet with the source rewritten to `(public_ip, public port)`.
               * `inbound(p)`: if `p.dst_port` is mapped, return the packet with its destination rewritten to the private
                 endpoint; otherwise return `std::nullopt` (drop).

               `std::pair<A, B>` groups two values (`.first`, `.second`); pairs compare lexicographically, so they work as
               `std::map` keys.
               """,
               r"""
               namespace ex7_2 {
               struct Packet { uint32_t src_ip; uint16_t src_port; uint32_t dst_ip; uint16_t dst_port; };
               struct Nat {
                   uint32_t public_ip = 0;
                   uint16_t next_port = 50000;
                   std::map<std::pair<uint32_t, uint16_t>, uint16_t> out_map;   // private endpoint -> public port
                   std::map<uint16_t, std::pair<uint32_t, uint16_t>> in_map;    // public port -> private endpoint

                   Packet outbound(Packet p) {
                       // TODO
                       return p;
                   }
                   std::optional<Packet> inbound(Packet p) {
                       // TODO
                       return std::nullopt;
                   }
               };
               }
               """,
               r"""
               namespace ex7_2 {
               struct Packet { uint32_t src_ip; uint16_t src_port; uint32_t dst_ip; uint16_t dst_port; };
               struct Nat {
                   uint32_t public_ip = 0;
                   uint16_t next_port = 50000;
                   std::map<std::pair<uint32_t, uint16_t>, uint16_t> out_map;   // private endpoint -> public port
                   std::map<uint16_t, std::pair<uint32_t, uint16_t>> in_map;    // public port -> private endpoint

                   Packet outbound(Packet p) {
                       auto key = std::make_pair(p.src_ip, p.src_port);
                       auto it = out_map.find(key);
                       uint16_t pub;
                       if (it == out_map.end()) {              // first packet of this flow: new mapping
                           pub = next_port++;
                           out_map[key] = pub;
                           in_map[pub] = key;
                       } else {
                           pub = it->second;                   // existing flow: reuse
                       }
                       p.src_ip = public_ip;
                       p.src_port = pub;
                       return p;
                   }
                   std::optional<Packet> inbound(Packet p) {
                       auto it = in_map.find(p.dst_port);
                       if (it == in_map.end()) return std::nullopt;   // unsolicited: drop
                       p.dst_ip = it->second.first;
                       p.dst_port = it->second.second;
                       return p;
                   }
               };
               }
               """,
               r"""
               {
                   auto ip = [](const char* s) { return lib7::parse_ipv4(s).value_or(0); };
                   auto show = [](const ex7_2::Packet& p) {
                       return lib7::format_ipv4(p.src_ip) + ":" + std::to_string(p.src_port) + " -> " +
                              lib7::format_ipv4(p.dst_ip) + ":" + std::to_string(p.dst_port);
                   };
                   ex7_2::Nat nat;
                   nat.public_ip = ip("203.0.113.5");
                   uint32_t laptop = ip("192.168.1.10"), phone = ip("192.168.1.11"), server = ip("93.184.216.34");

                   auto o1 = nat.outbound({laptop, 5555, server, 80});
                   auto o2 = nat.outbound({phone, 5555, server, 80});        // same private port, other host
                   auto o3 = nat.outbound({laptop, 5555, ip("1.1.1.1"), 53}); // same flow source, reused mapping
                   std::cout << "out: " << show(o1) << "\nout: " << show(o2) << "\nout: " << show(o3) << "\n";
                   CHECK_EQ(lib7::format_ipv4(o1.src_ip), "203.0.113.5");
                   CHECK_EQ(o1.src_port, 50000);
                   CHECK_EQ(o2.src_port, 50001);
                   CHECK_EQ(o3.src_port, 50000);
                   CHECK_EQ(o1.dst_port, 80);                                 // destination untouched

                   auto i1 = nat.inbound({server, 80, nat.public_ip, 50001});
                   CHECK(i1.has_value());
                   if (i1) std::cout << "in:  " << show(*i1) << "\n";
                   CHECK_EQ(i1 ? lib7::format_ipv4(i1->dst_ip) : std::string("<dropped>"), "192.168.1.11");
                   CHECK_EQ(i1 ? i1->dst_port : 0, 5555);
                   CHECK(!nat.inbound({ip("198.51.100.66"), 4444, nat.public_ip, 50007}).has_value());  // unsolicited
               }
               """,
               r"""
               Two maps give O(log n) lookups in both directions. Our NAT keys only on the private endpoint (an
               *endpoint-independent* mapping, which is why `o3` reuses port 50000). Real NATs also track the protocol, expire idle
               mappings after a timeout, and often allow a reply only from the remote endpoint that was originally contacted.
               """)
    B.question("why", r"""Why can't you run a web server on your laptop at home and have a friend connect to your public IP, unless
    you configure "port forwarding"? And why do two home devices both using source port 5555 not collide?""",
               r"""
               An inbound connection attempt arrives at the router's public IP with **no mapping** yet (mappings are only created
               by *outbound* packets), so the NAT drops it. **Port forwarding** is a manually configured, permanent mapping
               (public port 80 → 192.168.1.10:80). As a side effect, NAT behaves like a simple inbound firewall.
               The two devices do not collide because the NAT gives each flow its **own public port**, so the public side sees
               two different endpoints. *Misconception:* "NAT is a security feature". It blocks unsolicited inbound traffic only
               incidentally, and it breaks the end-to-end model that IPv6 restores.
               """)

    # ------------------------------------------------------------------ 7.3 DHCP
    lo, hi = ip2int("192.168.1.100"), ip2int("192.168.1.102")
    d = DhcpPy(lo, hi)
    ev = []   # (op, mac, ip or None) -> expected
    def rec(op, mac, arg=None):
        if op == "offer":
            r = d.offer(mac)
            ev.append((op, mac, None, str(ipaddress.IPv4Address(r)) if r is not None else "<none>"))
        elif op == "request":
            r = d.request(mac, ip2int(arg))
            ev.append((op, mac, arg, "ACK" if r else "NAK"))
        else:
            d.release(mac)
            ev.append((op, mac, None, "-"))
    rec("offer", "A"); rec("request", "A", "192.168.1.100")
    rec("offer", "B"); rec("request", "B", "192.168.1.101")
    rec("offer", "A")
    rec("offer", "C"); rec("request", "C", "192.168.1.102")
    rec("offer", "D"); rec("request", "D", "192.168.1.101")
    rec("release", "B"); rec("offer", "D"); rec("request", "D", "192.168.1.101")
    B.md(r"""
    ## 7.3 DHCP: getting an address automatically

    A new device has no IP address, no mask, no gateway. **DHCP** (Dynamic Host Configuration
    Protocol) provides all of them. It runs over **UDP** (a transport protocol that sends single
    messages to a port with no connection setup), from client port 68 to server port 67, in four steps
    (**DORA**):

    ```
    client (no IP yet)                                              DHCP server (home box)
      |-- Discover  src 0.0.0.0 -> dst 255.255.255.255 (broadcast) -->|  "any DHCP server?"
      |<-- Offer    "you may use 192.168.1.23 /24, gateway .1, DNS .1, lease 24 h"
      |-- Request   (broadcast) "I take 192.168.1.23 from server X" ->|  other servers withdraw
      |<-- Ack      "confirmed; lease starts now" --------------------|
    ```

    The client identifies itself by its **MAC** address. The address is **leased** for a limited time,
    and the client renews at about half the lease. `255.255.255.255` is the *limited broadcast*
    address: every host on the local link, never forwarded by routers.
    """)
    B.exercise("7.3", "A DHCP server's address pool",
               r"""
               The server owns the inclusive range `[pool_start, pool_end]` and `leases` maps MAC → IP.
               * `offer(mac)`: the MAC's existing lease if it has one; otherwise the **lowest** pool address not leased to
                 anyone; `std::nullopt` if the pool is exhausted.
               * `request(mac, ip)`: **ACK** (`true`) if `ip` is in the pool and not leased to a *different* MAC: record the
                 lease, replacing any old lease of this MAC. Otherwise **NAK** (`false`).
               * `release(mac)`: forget the MAC's lease.
               """,
               r"""
               namespace ex7_3 {
               struct DhcpServer {
                   uint32_t pool_start = 0, pool_end = 0;
                   std::map<std::string, uint32_t> leases;   // MAC -> IP

                   std::optional<uint32_t> offer(const std::string& mac) { return std::nullopt; }   // TODO
                   bool request(const std::string& mac, uint32_t ip)      { return false; }          // TODO
                   void release(const std::string& mac)                   { }                        // TODO
               };
               }
               """,
               r"""
               namespace ex7_3 {
               struct DhcpServer {
                   uint32_t pool_start = 0, pool_end = 0;
                   std::map<std::string, uint32_t> leases;   // MAC -> IP

                   // helper: which MAC holds ip ("" if free)
                   std::string owner(uint32_t ip) const {
                       for (const auto& kv : leases)
                           if (kv.second == ip) return kv.first;
                       return "";
                   }
                   std::optional<uint32_t> offer(const std::string& mac) {
                       auto it = leases.find(mac);
                       if (it != leases.end()) return it->second;              // returning client: same address
                       for (uint32_t ip = pool_start; ip <= pool_end; ++ip)
                           if (owner(ip).empty()) return ip;                    // lowest free address
                       return std::nullopt;                                     // pool exhausted
                   }
                   bool request(const std::string& mac, uint32_t ip) {
                       if (ip < pool_start || ip > pool_end) return false;
                       std::string o = owner(ip);
                       if (!o.empty() && o != mac) return false;                // taken by someone else: NAK
                       leases[mac] = ip;                                        // ACK (replaces an old lease)
                       return true;
                   }
                   void release(const std::string& mac) { leases.erase(mac); }
               };
               }
               """,
               fill(r"""
               {
                   auto ip = [](const char* s) { return lib7::parse_ipv4(s).value_or(0); };
                   ex7_3::DhcpServer srv;
                   srv.pool_start = ip("192.168.1.100");
                   srv.pool_end   = ip("192.168.1.102");
                   struct Ev { const char* op; const char* mac; const char* arg; const char* want; };
                   std::vector<Ev> events = {
               @EV@
                   };
                   for (const auto& e : events) {
                       std::string got;
                       std::string op = e.op;
                       if (op == "offer") {
                           auto r = srv.offer(e.mac);
                           got = r ? lib7::format_ipv4(*r) : "<none>";
                       } else if (op == "request") {
                           got = srv.request(e.mac, ip(e.arg)) ? "ACK" : "NAK";
                       } else {
                           srv.release(e.mac);
                           got = "-";
                       }
                       std::cout << op << "(" << e.mac << (e.arg[0] ? std::string(", ") + e.arg : "") << ") -> " << got << "\n";
                       CHECK_EQ(got, e.want);
                   }
               }
               """, EV="\n".join(f'        {{"{op}", "{mac}", "{arg or ""}", "{want}"}},' for op, mac, arg, want in ev)),
               r"""
               Keying leases by MAC is what makes a returning device get the **same** address (A's second offer). The NAK for D
               shows why the *Request* step exists: an offer is not a reservation, and the server re-checks ownership at
               request time. Once B releases its lease, D obtains `.101`. Real servers also expire leases whose owners stop
               renewing.
               """)
    B.question("why", r"""Your laptop reports the address 169.254.37.12 and cannot reach anything. What went wrong? And why is the
    DHCP Request sent as a broadcast even though the client already knows the server's address?""",
               r"""
               169.254.0.0/16 is **link-local**: the OS self-assigns such an address when **no DHCP server answered** (the
               server is down, the Wi-Fi association failed, or the cable is bad). Link-local addresses work only on the local
               link and have no gateway, so there is no Internet access.

               The Request is broadcast because (1) the client still has no confirmed IP address to use as a source, and
               (2) **several** servers may have made offers: the broadcast tells all of them which offer was accepted, so the
               others can release the addresses they tentatively offered.
               """)

    # ------------------------------------------------------------------ 7.4 DNS
    name = "www.example.com"
    q = dns_query(0x1a2b, name, 1)
    B.md(r"""
    ## 7.4 DNS: names to addresses

    Humans use names; IP uses addresses. **DNS** (Domain Name System) is a distributed database that
    maps names to **records**: `A` (IPv4 address), `AAAA` (IPv6), `CNAME` (alias for another name),
    `MX` (mail server), `NS` (which servers are authoritative for a zone). A **zone** is a part of the name tree
    run by one organisation (e.g. `example.com`); its **authoritative** servers hold the original records, while
    everyone else only caches them. Names form a tree read right to left; the top level below the root (`.com`,
    `.org`, `.de`) is the **TLD** (top-level domain):

    ```
    stub resolver (in your OS)
       └─ asks ─► recursive resolver (ISP / public, often via the home box's DNS forwarder)
                     ├─► root server:  "who handles .com?"        -> the .com servers
                     ├─► .com server:  "who handles example.com?" -> example.com's servers
                     └─► authoritative server for example.com: "www.example.com A?" -> 93.184.216.34
    ```

    Every answer carries a **TTL** (a *time in seconds*, unrelated to IP's hop count), and resolvers
    **cache** answers for that long, so most lookups never reach the root. Queries normally use UDP
    port 53; large answers fall back to TCP. On the wire a name is a sequence of **labels**, each
    prefixed by its length, ending in a zero byte: `www.example.com` → `03 www 07 example 03 com 00`.
    """)
    B.exercise("7.4a", "Encode a DNS name",
               fill(r"""
               `encode_dns_name(name)` produces the label format. Accept an optional trailing dot. Return an **empty** vector if
               any label is empty (e.g. `"a..b"`) or longer than 63 bytes (the length byte has 6 usable bits).
               For `"@N@"`:
               ```
               @D@
               ```
               """, N=name, D=hexdump_py(dns_name(name))),
               r"""
               namespace ex7_4a {
               std::vector<uint8_t> encode_dns_name(const std::string& name) {
                   // TODO
                   return {};
               }
               }
               """,
               r"""
               namespace ex7_4a {
               std::vector<uint8_t> encode_dns_name(const std::string& name) {
                   std::string n = name;
                   if (!n.empty() && n.back() == '.') n.pop_back();      // "example.com." == "example.com"
                   std::vector<uint8_t> out;
                   size_t start = 0;
                   while (true) {
                       size_t dot = n.find('.', start);                   // std::string::npos if none
                       std::string label = n.substr(start, dot == std::string::npos ? std::string::npos : dot - start);
                       if (label.empty() || label.size() > 63) return {};
                       out.push_back(uint8_t(label.size()));              // length prefix
                       out.insert(out.end(), label.begin(), label.end());
                       if (dot == std::string::npos) break;
                       start = dot + 1;
                   }
                   out.push_back(0);                                      // the root label ends the name
                   return out;
               }
               }
               """,
               fill(r"""
               {
                   auto e = ex7_4a::encode_dns_name("@N@");
                   hexdump(e);
                   CHECK_EQ(e, (std::vector<uint8_t>{@B@}));
                   CHECK_EQ(ex7_4a::encode_dns_name("@N@."), e);                 // trailing dot
                   CHECK_EQ(ex7_4a::encode_dns_name("localhost").size(), @L@u);
                   CHECK(ex7_4a::encode_dns_name("a..b").empty());
                   CHECK(ex7_4a::encode_dns_name(std::string(64, 'x') + ".com").empty());
               }
               """, N=name, B=", ".join(f"0x{x:02x}" for x in dns_name(name)), L=len(dns_name("localhost"))),
               r"""
               `std::string::find` returns `npos` when there is no further dot, which marks the last label. Length-prefixed
               labels (rather than dots) let a parser skip a label without scanning for a delimiter, the same idea as the
               length-prefixed framing you will build in Part 9.
               """, snippet_key="dns_name")
    B.md(r"""
    A DNS **query message** is a 12-byte header followed by the question:

    ```
    offset 0  ID (2)         random; echoed in the answer to match queries with replies
           2  flags (2)      0x0100 = standard query with RD ("recursion desired") set
           4  QDCOUNT (2)    number of questions = 1
           6  ANCOUNT, NSCOUNT, ARCOUNT (2 each) = 0 in a query
    12        QNAME          encoded name
              QTYPE (2)      1 = A, 28 = AAAA
              QCLASS (2)     1 = IN (Internet)
    ```
    """)
    B.provided("lib7b", [("7.4a", "dns_name")])
    B.exercise("7.4b", "Build a complete DNS query",
               fill(r"""
               `build_dns_query(id, name, qtype)` returns the full message. Use `lib7::write_be16` and `lib7b::encode_dns_name`.
               For ID 0x1a2b, `"@N@"`, type A, the correct @LEN@ bytes are:
               ```
               @D@
               ```
               """, N=name, LEN=len(q), D=hexdump_py(q)),
               r"""
               namespace ex7_4b {
               std::vector<uint8_t> build_dns_query(uint16_t id, const std::string& name, uint16_t qtype) {
                   // TODO
                   return {};
               }
               }
               """,
               r"""
               namespace ex7_4b {
               std::vector<uint8_t> build_dns_query(uint16_t id, const std::string& name, uint16_t qtype) {
                   std::vector<uint8_t> m(12, 0);                  // header, counts start at zero
                   lib7::write_be16(&m[0], id);
                   lib7::write_be16(&m[2], 0x0100);                // RD = 1
                   lib7::write_be16(&m[4], 1);                     // one question
                   auto qname = lib7b::encode_dns_name(name);
                   m.insert(m.end(), qname.begin(), qname.end());
                   uint8_t tail[4];
                   lib7::write_be16(tail, qtype);
                   lib7::write_be16(tail + 2, 1);                  // class IN
                   m.insert(m.end(), tail, tail + 4);
                   return m;
               }
               }
               """,
               fill(r"""
               {
                   auto m = ex7_4b::build_dns_query(0x1a2b, "@N@", 1);
                   hexdump(m);
                   CHECK_EQ(m, (std::vector<uint8_t>{
               @B@
                   }));
                   CHECK_EQ(ex7_4b::build_dns_query(7, "@N@", 28).size(), @LEN@u);   // AAAA: same size
               }
               """, N=name, B=cpp_bytes(q, indent="        "), LEN=len(q)),
               r"""
               These are the exact bytes a resolver library puts in the payload of a UDP datagram to port 53; tools such as `dig`
               send nothing more. The answer echoes the ID and the question, then appends resource records whose names are often
               *compressed* (a 2-byte pointer back to an earlier name).
               """)
    B.question("why", r"""Resolvers cache answers for their TTL. What is gained, and what goes wrong when an operator moves a
    website to a new IP address but the old record had TTL = 86400?""",
               r"""
               **Gain:** most lookups are answered from a nearby cache in about a millisecond instead of a multi-server
               walk from the root, and the load on root and TLD servers stays manageable.
               **Cost, staleness:** caches may keep returning the **old** IP for up to 86 400 s (24 h) after the change. Operators
               therefore lower the TTL (e.g. to 60 s) a day **before** a migration. *Misconception:* "DNS changes propagate".
               Nothing is pushed; old cached answers simply expire.
               """)

    # ------------------------------------------------------------------ 7.5 walkthrough
    B.md(r"""
    ## 7.5 Putting it together

    You now know every service a home network needs. The next question is a classic interview
    prompt; answer it on paper before expanding the solution.
    """)
    B.question("concept", r"""A laptop joins a home Wi-Fi network and opens `http://example.com`. List, **in order**, every protocol
    exchange and every device involved until the first byte of the page arrives. (Plain HTTP on port 80, so no encryption
    step.)""",
               r"""
               1. **Wi-Fi association** (L1/L2): the laptop's NIC joins the **AP**'s wireless network (the radio-level
                  handshake that admits a device to the Wi-Fi LAN; its details are beyond this notebook).
               2. **DHCP DORA** (UDP 68→67; Discover and Request are broadcast to `ff:ff:ff:ff:ff:ff`, Offer and Ack may be unicast): the AP bridges them to the box's **DHCP
                  server**, and the laptop learns, e.g., `192.168.1.23/24`, gateway `192.168.1.1`, DNS server `192.168.1.1`.
               3. **ARP** for `192.168.1.1` (broadcast request, unicast reply): the laptop needs the gateway's MAC because
                  the gateway is also its DNS server, and every remote host is reached through it.
               4. **DNS** query `example.com A?` (UDP port 53) to the box's **DNS forwarder**. On a cache miss the forwarder
                  sends it on: **router** → **NAT** rewrites the source to the public IP → **modem** modulates it onto
                  DSL/coax/fibre → **ISP routers** (longest-prefix match at each hop, TTL−1, new L2 header per link) → the
                  **recursive resolver**, which asks root → `.com` → authoritative servers if its cache is cold. The answer
                  returns along the reverse path; NAT translates it back, and the forwarder caches it.
               5. The laptop compares the server IP with its own subnet: it is not local, so the next hop is the gateway (ARP
                  cache hit this time).
               6. **TCP connection setup** to `server:80`: a short exchange of three segments (Part 8), each packet crossing
                  laptop NIC → AP → router (+NAT, new public port) → modem → ISP routers → **web server**, and back.
               7. **HTTP** `GET /` request over that connection; the server's response travels back through the ISP → modem →
                  router/NAT (destination rewritten to the laptop) → switch/AP → laptop NIC (DMA) → OS stack → browser.

               Common omissions: the ARP step, the fact that DNS runs *before* any TCP connection exists, and NAT rewriting
               *both* directions.
               """)
    B.recap(
        ["RFC 1918 private ranges: 10/8, 172.16/12, 192.168/16; also 127/8 loopback, 169.254/16 link-local, 100.64/10 shared.",
         "NAT/PAT maps (private IP, port) ↔ (public IP, public port); mappings are created by outbound traffic; unmapped inbound traffic is dropped.",
         "DHCP DORA hands out IP, mask, gateway, DNS and a lease; broadcast because the client has no address yet.",
         "DNS resolves names through a hierarchy (root → TLD → authoritative) via a recursive resolver; answers are cached for their TTL.",
         "Opening a web page = DHCP → ARP → DNS → TCP → HTTP, crossing AP, router/NAT, modem, ISP routers."],
        ["whether any given address is private, and why 172.32.0.1 is not;",
         "how NAT lets many devices share one public IP, and why inbound connections fail;",
         "each DHCP message and why the Request is broadcast;",
         "the wire format of a DNS query, and what a DNS TTL means;",
         "the full sequence of events when a laptop joins Wi-Fi and loads a page."])
