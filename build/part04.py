from math import log2

from nb import fill


def manchester(b: int):
    out = []
    for i in range(7, -1, -1):
        bit = (b >> i) & 1
        out += [0, 1] if bit else [1, 0]   # IEEE 802.3: 1 = low->high, 0 = high->low
    return out


def ring_sim():
    N = 8
    slots = [0] * N
    head = tail = count = dropped = 0
    polled = []

    def rx(p):
        nonlocal head, count, dropped
        if count == N:
            dropped += 1
            return False
        slots[head] = p
        head = (head + 1) & (N - 1)
        count += 1
        return True

    def poll():
        nonlocal tail, count
        if count == 0:
            return None
        p = slots[tail]
        tail = (tail + 1) & (N - 1)
        count -= 1
        return p

    accepted1 = sum(rx(p) for p in range(10))
    first3 = [poll() for _ in range(3)]
    accepted2 = sum(rx(p) for p in range(10, 13))
    rest = []
    while True:
        p = poll()
        if p is None:
            break
        rest.append(p)
    return accepted1, dropped, first3, accepted2, rest


def build(B):
    B.part("4", "Physical layer and hardware")
    B.md(r"""
    # Part 4 — Physical layer and hardware

    ## 4.1 Transmission media

    The **medium** is what physically carries the signal:

    | medium | signal | typical use | notes |
    |---|---|---|---|
    | twisted-pair copper | voltage | Ethernet cables in homes and offices | ≤ 100 m per cable run; pairs are twisted to cancel interference |
    | coaxial copper | voltage (radio frequencies) | cable TV / cable Internet | shielded; shared by a whole neighbourhood |
    | optical fibre | light pulses | long haul, data centres, fibre-to-the-home | km to 100 km+ per span; immune to electrical noise |
    | radio | electromagnetic waves | Wi-Fi, cellular | shared by everyone in range; interference; no cable |

    Guided media (copper, fibre) confine the signal to a cable. Radio is **broadcast** by nature:
    every receiver in range hears every transmission.
    """)
    B.question("why", r"""Why do long-distance and data-centre links use fibre rather than copper, even though the signal
    speed in both is about ⅔ of *c*?""",
               r"""
               Not for *propagation* speed, which is similar. Fibre wins on **attenuation and bandwidth**: light in glass
               loses very little power per km and supports enormous rates, so spans of tens of km need no amplifier, while
               copper at high rates degrades within metres to about 100 m. Fibre also ignores electromagnetic interference
               and cannot be tapped by induction. *Misconception:* "fibre is faster because light is faster than
               electricity". Both signals travel at roughly 2·10⁸ m/s.
               """)

    # ------------------------------------------------------------------ 4.2
    B.md(r"""
    ## 4.2 Bits as signals: symbols and baud

    The transmitter sends one **symbol** per time slot. A symbol is one distinguishable signal
    state, such as a voltage level or a light intensity. The **symbol rate** is measured in **baud**
    (symbols per second). With $M$ distinguishable levels a symbol carries $\log_2 M$ bits, so

    $$\text{bit rate} = \text{baud} \times \log_2 M.$$

    ```
    M = 2 levels (1 bit/symbol)        M = 4 levels (2 bits/symbol)
    +1 ‾‾‾|   |‾‾‾                     +3 ‾‾‾|        11
          |   |                        +1    |‾‾‾|    10
    -1    |___|                        -1        |    01
                                       -3        |___ 00
    ```

    **Noise** (random disturbance added by the medium and electronics) blurs the received level.
    When levels are closer together, a smaller disturbance turns one symbol into its neighbour, and
    the result is a **bit error**.
    """)
    B.question("compute", r"""A link sends 125 Mbaud with 4 levels per symbol on each of 4 wire pairs in parallel.
    What is the total bit rate? And why not simply use 1024 levels to go 5× faster?""",
               f"""
               Per pair: 125·10⁶ × log₂4 = {125e6*log2(4)/1e6:g} Mb/s; four pairs: **{4*125e6*log2(4)/1e6:g} Mb/s**. This is
               roughly how gigabit Ethernet over copper works; the real scheme is more elaborate, and some levels
               carry error-correction redundancy rather than data.

               With 1024 levels (10 bits/symbol) at the same maximum voltage, adjacent levels are much closer than with
               4 levels ({1023/3:.0f}×), so ordinary noise causes constant symbol errors. Noise, not cleverness, limits bits per symbol.
               """)

    # ------------------------------------------------------------------ 4.3
    B.md(r"""
    ## 4.3 Line coding and clock recovery

    The receiver must also know **when** to sample each symbol. Its clock drifts relative to the
    sender's, so it re-synchronises on signal **transitions** (changes of level). In plain
    **NRZ** coding (non-return-to-zero: high = 1, low = 0) a long run of identical bits has no
    transitions, and the receiver loses count of how many bits went by.

    **Manchester coding**, used by 10 Mb/s Ethernet, guarantees a transition in the **middle of
    every bit**. Each bit becomes two half-bit levels; IEEE 802.3 (the Ethernet standard) sends
    `1` as low→high and `0` as high→low:

    ```
    bits:          1       0       1       1       0
    NRZ:        ‾‾‾‾‾‾‾|_______|‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾|_______
    Manchester: ___|‾‾‾ ‾‾‾|___ ___|‾‾‾ ___|‾‾‾ ‾‾‾|___
    halves:      0   1   1   0   0   1   0   1   1   0
    ```

    The price is two signal halves per bit, i.e. double the symbol rate. Faster Ethernets use
    cheaper codes (e.g. 64b/66b) that add only a few extra bits per block to guarantee transitions.
    """)
    x = 0xA5
    B.exercise("4.3", "Manchester encoder and decoder",
               fill(r"""
               * `manchester_encode(b)`: return 16 half-bit levels (`1` = high, `0` = low) for the byte `b`, **most
                 significant bit first**. (Real Ethernet transmits each byte least-significant bit first; MSB-first keeps this
                 exercise readable.)
               * `manchester_decode(levels)`: the inverse. Return `std::nullopt` if `levels.size() != 16` or any pair is
                 `00` or `11`: such a pair has no mid-bit transition, so it is a coding violation.

               For `0x@X@` the expected output is `@E@`.
               """, X=f"{x:02X}", E="".join(map(str, manchester(x)))),
               r"""
               namespace ex4_3 {
               std::vector<uint8_t> manchester_encode(uint8_t b) {
                   // TODO
                   return {};
               }
               std::optional<uint8_t> manchester_decode(const std::vector<uint8_t>& levels) {
                   // TODO
                   return std::nullopt;
               }
               }
               """,
               r"""
               namespace ex4_3 {
               std::vector<uint8_t> manchester_encode(uint8_t b) {
                   std::vector<uint8_t> out;
                   for (int i = 7; i >= 0; --i) {             // MSB first
                       bool bit = (b >> i) & 1;
                       if (bit) { out.push_back(0); out.push_back(1); }   // 1: low -> high
                       else     { out.push_back(1); out.push_back(0); }   // 0: high -> low
                   }
                   return out;
               }
               std::optional<uint8_t> manchester_decode(const std::vector<uint8_t>& levels) {
                   if (levels.size() != 16) return std::nullopt;
                   uint8_t b = 0;
                   for (int i = 0; i < 8; ++i) {
                       uint8_t first = levels[2 * i], second = levels[2 * i + 1];
                       if (first == second) return std::nullopt;         // no transition: violation
                       b = uint8_t((b << 1) | (second == 1 ? 1 : 0));    // low->high means 1
                   }
                   return b;
               }
               }
               """,
               fill(r"""
               {
                   auto enc = ex4_3::manchester_encode(0x@X@);
                   CHECK_EQ(enc, (std::vector<uint8_t>{@E@}));
                   CHECK_EQ(ex4_3::manchester_encode(0x00).size(), 16u);
                   CHECK_EQ(int(ex4_3::manchester_decode(enc).value_or(0)), 0x@X@);
                   bool all_round_trip = true;
                   for (int v = 0; v < 256; ++v) {
                       auto d = ex4_3::manchester_decode(ex4_3::manchester_encode(uint8_t(v)));
                       if (!d || *d != v) all_round_trip = false;
                   }
                   CHECK(all_round_trip);
                   auto bad = enc;
                   if (bad.size() == 16) bad[3] = bad[2];          // destroy one mid-bit transition
                   CHECK(!ex4_3::manchester_decode(bad).has_value());
               }
               """, X=f"{x:02X}", E=", ".join(map(str, manchester(x)))),
               r"""
               Every bit produces exactly one mid-bit transition, so even `0x00` or `0xFF` (long runs in NRZ) toggles 8 times
               per byte. Rejecting `00`/`11` pairs is a free error check: a single corrupted half-bit usually produces an
               impossible pair. Note the direct link to §1.3: the encoder is just "test bit *i*, most significant first".
               """)

    # ------------------------------------------------------------------ 4.4
    B.md(r"""
    ## 4.4 The NIC: network interface controller

    A **NIC** (network interface controller, or card) is the hardware that attaches a host to a
    link. It has two halves: the **PHY** chip (physical layer: converts between bits and signals,
    including line coding) and the **MAC** (media access control) logic (link layer: frames, addresses, error checks). The NIC:

    * **serialises**: turns the bytes of an outgoing frame into a timed sequence of symbols, and
      *deserialises* incoming signals back into bytes;
    * **owns a MAC address**: a 48-bit identifier programmed at the factory, written as six hex
      bytes, e.g. `3c:22:fb:12:ab:9e`;
    * **filters**: keeps frames addressed to its own MAC address (or to "everyone") and silently
      ignores the rest; *promiscuous mode*, used by packet sniffers, disables this filter;
    * **checks** each frame's error-detection trailer and drops corrupted frames;
    * **moves frames to and from host memory** without the CPU copying each byte, which is the next topic.
    """)
    B.question("concept", r"""You plug a laptop into a busy network and run a packet sniffer *without* promiscuous mode.
    Which frames does the operating system get to see?""",
               r"""
               Only frames the NIC accepted: those addressed to **its own MAC address**, plus frames addressed to everyone
               or to groups it has joined, plus the frames it sends itself. Other hosts' traffic is dropped **in hardware**
               before the OS ever sees it. On a switched network (§4.7) most of it never reaches your port anyway.
               *Misconception:* "the OS receives everything and discards most of it". The filter is in the NIC, which is
               why it can keep up with line rate.
               """)

    # ------------------------------------------------------------------ 4.5
    a1, dropped, first3, a2, rest = ring_sim()
    B.md(r"""
    ## 4.5 DMA and ring buffers

    At 10 Gb/s a CPU cannot afford to copy every byte itself. With **DMA** (direct memory access)
    the NIC reads and writes host RAM on its own. The **driver** (the OS code controlling the NIC)
    and the NIC share a **ring buffer**: a fixed-size circular array of *descriptors*, each pointing
    at a packet buffer in RAM.

    On receive, the NIC DMA-writes a frame into the slot at **head** and advances head; it then
    raises an **interrupt** (a hardware signal telling the CPU "work is ready"). The driver consumes
    frames from **tail**. If the driver falls behind and the ring is full, the NIC must **drop**
    new frames.

    ```
              tail (driver reads next)       head (NIC writes next)
                 v                              v
        +-----+-----+-----+-----+-----+-----+-----+-----+
        |     |  p3 |  p4 |  p5 |  p6 |  p7 |     |     |    N = 8 slots
        +-----+-----+-----+-----+-----+-----+-----+-----+
        index advance with wrap-around:  i = (i + 1) & (N - 1)    (N a power of two)
    ```
    """)
    B.exercise("4.5", "A receive ring",
               r"""
               Complete `RxRing`. Track fullness with `count`. `nic_receive` stores a packet id at `head`, or, if the ring
               is full, increments `dropped` and returns `false`. `driver_poll` returns the oldest packet, or `std::nullopt`
               when the ring is empty. Advance indices with the mask trick shown above.
               (`std::array<int, N>` is a fixed-size array; `static constexpr` makes `N` a compile-time constant.)
               """,
               r"""
               namespace ex4_5 {
               struct RxRing {
                   static constexpr size_t N = 8;     // must be a power of two
                   std::array<int, N> slot{};         // stands in for descriptors -> packet buffers
                   size_t head = 0, tail = 0, count = 0;
                   uint64_t dropped = 0;

                   bool nic_receive(int pkt) {
                       // TODO
                       return false;
                   }
                   std::optional<int> driver_poll() {
                       // TODO
                       return std::nullopt;
                   }
               };
               }
               """,
               r"""
               namespace ex4_5 {
               struct RxRing {
                   static constexpr size_t N = 8;     // must be a power of two
                   std::array<int, N> slot{};         // stands in for descriptors -> packet buffers
                   size_t head = 0, tail = 0, count = 0;
                   uint64_t dropped = 0;

                   bool nic_receive(int pkt) {
                       if (count == N) { ++dropped; return false; }   // ring full: the NIC drops
                       slot[head] = pkt;
                       head = (head + 1) & (N - 1);                    // same as % N, but one AND
                       ++count;
                       return true;
                   }
                   std::optional<int> driver_poll() {
                       if (count == 0) return std::nullopt;
                       int pkt = slot[tail];
                       tail = (tail + 1) & (N - 1);
                       --count;
                       return pkt;
                   }
               };
               }
               """,
               fill(r"""
               {
                   ex4_5::RxRing ring;
                   int accepted = 0;
                   for (int p = 0; p < 10; ++p) accepted += ring.nic_receive(p);   // burst of 10 frames
                   CHECK_EQ(accepted, @A1@);
                   CHECK_EQ(ring.dropped, @D@u);

                   std::vector<int> first;
                   for (int i = 0; i < 3; ++i) first.push_back(ring.driver_poll().value_or(-1));
                   CHECK_EQ(first, (std::vector<int>{@F3@}));

                   int accepted2 = 0;
                   for (int p = 10; p < 13; ++p) accepted2 += ring.nic_receive(p);  // wraps around the end
                   CHECK_EQ(accepted2, @A2@);

                   std::vector<int> rest;
                   for (int i = 0; i < 20; ++i) {          // bounded loop: never spins forever
                       auto p = ring.driver_poll();
                       if (!p) break;
                       rest.push_back(*p);
                   }
                   CHECK_EQ(rest, (std::vector<int>{@REST@}));
               }
               """, A1=a1, D=dropped, F3=", ".join(map(str, first3)), A2=a2, REST=", ".join(map(str, rest))),
               fill(r"""
               The first burst fills all 8 slots, and frames 8 and 9 are dropped **by the NIC**: the OS never learns
               their contents, only a "missed" counter increments (visible on Linux with `ip -s link`). After the driver
               frees 3 slots, frames 10–12 wrap around to indices 0–2, and the order is still preserved: `@REST@`.
               Using a power-of-two size turns `% N` into a single AND, the same mask idea as §1.3.
               """, REST=", ".join(map(str, rest))))
    B.question("why", r"""A server's NIC reports thousands of "rx missed" drops per second, yet the link is only 30% utilised.
    What is the likely bottleneck?""",
               r"""
               The **host**, not the wire: the driver/CPU is not emptying the receive ring fast enough (too few CPU cores
               handling interrupts, a ring that is too small for bursts, or an application that is too slow). Average
               utilisation hides **bursts**: a microsecond-scale burst can fill a small ring even at 30% average load, which
               is the queuing lesson of §2.5 again. *Misconception:* "drops mean the network is congested". Here the queue
               that overflowed is inside your own machine.
               """)

    # ------------------------------------------------------------------ 4.6
    B.md(r"""
    ## 4.6 The modem: the edge of your home network

    A **modem** (modulator–demodulator) converts between digital bits and a signal suited to a
    medium that was *not* built for Ethernet. **Modulation** encodes bits by varying a carrier wave's
    amplitude, frequency, or phase; **demodulation** recovers them.

    * **DSL modem**: over the telephone company's copper pair.
    * **Cable modem**: over the cable-TV coaxial network, following the DOCSIS standard.
    * **ONT** (optical network terminal): for fibre-to-the-home, converts between light on the
      provider's fibre and Ethernet in your home.

    The modem is the **edge device** between your home network and the **ISP**'s (Internet service
    provider's) access network. It works at layers 1–2: it converts signals and frames, but it makes
    no routing decisions.
    """)
    B.question("why", r"""Why not simply run an Ethernet cable from your house to the ISP instead of using a modem?""",
               r"""
               Twisted-pair Ethernet is specified for **≤ 100 m**, while the ISP's equipment is often kilometres away.
               ISPs also reuse wiring that already exists (phone copper, TV coax, shared fibre), which uses different
               signalling and is shared among many homes. The modem adapts your standard Ethernet to that medium and to the
               ISP's access protocol. *Misconception:* "the modem is the router". Often they share one box, but modulation
               (L1/L2) and routing (L3) are different jobs.
               """)

    # ------------------------------------------------------------------ 4.7
    B.md(r"""
    ## 4.7 Hub vs switch vs router vs access point

    * **Hub** (L1, obsolete): repeats every incoming bit out of *all* other ports. All hosts share
      the bandwidth, and simultaneous senders **collide** (their signals overlap and are garbled).
    * **Switch** (L2): reads each frame's destination MAC address and forwards the frame only out of
      the port where that address lives.
    * **Router** (L3): connects *different* networks. It reads the destination IP address, picks the
      next hop, and forwards the packet inside a **new** L2 frame for the next link.
    * **Access point (AP)** (L2): bridges frames between Wi-Fi radio clients and wired Ethernet.

    A **LAN** (local area network) is a set of hosts that reach each other directly through
    switches and APs, with no router in between. Routers connect LANs to each other and to the Internet.

    ```
      host A            switch            router            host B
     [ L7 app ]                                            [ L7 app ]
     [ L4     ]                                            [ L4     ]
     [ L3     ]                          [ L3     ]        [ L3     ]
     [ L2     ]        [ L2     ]        [ L2     ]        [ L2     ]
     [ L1     ]~~~~~~~~[ L1     ]~~~~~~~~[ L1     ]~~~~~~~~[ L1     ]
    ```
    Each device decapsulates only as high as its job requires.
    """)
    B.question("predict", r"""A frame for host D arrives on port 1 of a 4-port device; D is on port 3.
    Where does it go if the device is (a) a hub, (b) a switch that already knows D's location?""",
               r"""
               (a) Hub: out of ports **2, 3, and 4**, i.e. everything except the port it came in on. The hub does not
               understand addresses; every host receives the frame, and all but D drop it in their NIC filter.
               (b) Switch: out of **port 3 only**. The other hosts never see it, which also improves privacy and lets
               different port pairs transfer data simultaneously.
               """)
    B.question("concept", r"""Of hub, switch, router and AP, which must parse the **IP** header of a packet it forwards? Which one
    rewrites the Ethernet source and destination addresses?""",
               r"""
               Only the **router** parses the IP header (L3), and it is also the one that builds a **new** Ethernet header for the
               next link, with its own MAC as the source and the next hop's MAC as the destination. Switches and APs forward
               frames with the MAC addresses unchanged. *Misconception:* "the destination MAC of my packet is the web
               server's MAC". It is the MAC of the next device on your link, usually your router. Part 6 shows how that
               MAC is found.
               """)

    # ------------------------------------------------------------------ 4.8
    B.md(r"""
    ## 4.8 The home "router" box

    The box your ISP gave you is several devices in one case:

    ```
                  ┌───────────────── home "router" box ───────────────────┐
     laptop ~~~~~~│~~ Wi-Fi AP ─┐                                          │
                  │             ├─ switch ── router + NAT ── WAN port ──────│──┐
     desktop =====│== LAN ports ┘               │                          │  │ Ethernet
                  │                   DHCP server, DNS forwarder           │  │
                  └────────────────────────────────────────────────────────┘  │
                                      modem / ONT (sometimes built in) ◄──────┘
                                           │  DSL / coax / fibre
                                          ISP ─── Internet
    ```

    * **AP + switch**: connect all home devices into one LAN.
    * **Router**: forwards packets between the home LAN and the ISP.
    * **DHCP server**: automatically hands each new device an IP address and network settings.
    * **NAT** (network address translation): lets every home device share the single public IP
      address the ISP gives you.
    * **DNS forwarder**: relays name lookups (e.g. `www.example.com` → IP address) to the ISP's DNS
      servers and caches the answers.
    """)
    B.question("concept", r"""Your Wi-Fi laptop prints to a printer plugged into a LAN port of the same home box. Which
    components of the box carry those frames? Is the router function involved?""",
               r"""
               The **AP** (radio → Ethernet) and the **switch** (to the printer's port). Both devices are on the **same LAN**,
               so frames are bridged at L2 and the router, NAT, and modem are not involved at all. The same LAN spans wired
               and wireless ports. *Misconception:* "everything goes through the router because the box is called a
               router". Only traffic leaving the LAN is routed.
               """)

    # ------------------------------------------------------------------ 4.9
    data = [0x41, 0x42, 0x43]
    ones = sum(bin(b).count("1") for b in data)
    B.md(r"""
    ## 4.9 Detecting bit errors: the parity bit

    Noise flips bits. The simplest detector is **even parity**: the sender appends one bit chosen so
    that the total number of 1-bits (data + parity) is **even**. The receiver recounts, and an odd
    total means an error was detected.

    ```
    data 1011 0010  -> four 1s  -> parity bit 0   total 4 (even)  ✓
    data 1011 0011  -> five 1s  -> parity bit 1   total 6 (even)  ✓
    ```

    Counting the 1-bits of a value is called **popcount**. The receiver cannot tell *which* bit
    flipped, only that an odd number of them did.
    """)
    B.exercise("4.9", "Even parity over a buffer",
               fill(r"""
               * `popcount8(b)`: the number of 1 bits in a byte (loop over bits, §1.3).
               * `even_parity_bit(data)`: the parity bit (0 or 1) for all bits of all bytes in `data`.
               * `parity_ok(data, p)`: `true` if data plus parity bit `p` contain an even number of 1s.

               For `{0x41, 0x42, 0x43}` there are @ONES@ one-bits.
               """, ONES=ones),
               r"""
               namespace ex4_9 {
               int popcount8(uint8_t b) { return 0; }                                        // TODO
               uint8_t even_parity_bit(const std::vector<uint8_t>& data) { return 0; }       // TODO
               bool parity_ok(const std::vector<uint8_t>& data, uint8_t p) { return false; } // TODO
               }
               """,
               r"""
               namespace ex4_9 {
               int popcount8(uint8_t b) {
                   int n = 0;
                   for (int i = 0; i < 8; ++i) n += (b >> i) & 1;
                   return n;
               }
               uint8_t even_parity_bit(const std::vector<uint8_t>& data) {
                   int ones = 0;
                   for (uint8_t b : data) ones += popcount8(b);
                   return uint8_t(ones % 2);          // 1 if odd, so that the total becomes even
               }
               bool parity_ok(const std::vector<uint8_t>& data, uint8_t p) {
                   return even_parity_bit(data) == p;
               }
               }
               """,
               fill(r"""
               {
                   CHECK_EQ(ex4_9::popcount8(0xB2), 4);
                   CHECK_EQ(ex4_9::popcount8(0xFF), 8);
                   std::vector<uint8_t> data = {0x41, 0x42, 0x43};
                   uint8_t p = ex4_9::even_parity_bit(data);
                   CHECK_EQ(int(p), @P@);
                   CHECK(ex4_9::parity_ok(data, p));

                   auto one_flip = data;  one_flip[1] ^= 0x08;                   // flip one bit
                   CHECK(!ex4_9::parity_ok(one_flip, p));                       // detected

                   auto two_flips = data; two_flips[0] ^= 0x01; two_flips[2] ^= 0x40;   // flip two bits
                   std::cout << "two-bit error detected? " << !ex4_9::parity_ok(two_flips, p) << "\n";
                   CHECK(ex4_9::parity_ok(two_flips, p));                       // NOT detected: parity is fooled
               }
               """, P=ones % 2),
               r"""
               XOR-ing all bits together gives the same answer (`popcount % 2` is the XOR of all bits). The last check passes
               precisely because parity is *fooled*: two flips change the number of 1s by 0 or ±2, and the parity of that number
               is unchanged. The next question asks what this means in practice.
               """)
    B.question("why", r"""Why does parity miss every 2-bit error, and why is that a serious weakness on real links?""",
               r"""
               Parity only captures the count of 1s **mod 2**. Any even number of flips (2, 4, …) leaves it unchanged, so
               parity detects only odd-sized errors. Real noise tends to arrive in **bursts** (a spike of interference
               corrupts several *adjacent* bits), so multi-bit errors are common and would slip through ~50% of the time.
               This motivates stronger codes: the 16-bit **Internet checksum** (Part 6), a simple sum that is better than parity
               but still fairly weak, and the 32-bit **CRC** that Ethernet appends to every frame (Part 5), which spreads each
               bit's influence over many check bits.
               """)
    B.recap(
        ["Media: copper (≤100 m for Ethernet), coax, fibre (long, clean), radio (shared, broadcast).",
         "bit rate = baud × log₂(levels); noise limits the number of levels; line codes such as Manchester guarantee transitions for clock recovery.",
         "The NIC serialises bits, owns a MAC address, filters and error-checks frames, and moves them via DMA through ring buffers (full ring = drop).",
         "Modem/ONT = signal conversion at the edge to the ISP. Hub L1, switch L2, AP L2, router L3.",
         "The home box = AP + switch + router + NAT + DHCP + DNS forwarder (± modem). Parity detects only odd numbers of bit errors."],
        ["the difference between baud and bit rate;",
         "what a NIC does between the cable and the CPU, including DMA rings and drops;",
         "which device handles which layer, and which one rewrites MAC addresses;",
         "what each function inside a home \"router\" does;",
         "why parity is not enough for real links."])
