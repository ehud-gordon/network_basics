from math import comb

from nb import fill


def binom_tail(n, p, k):
    return sum(comb(n, i) * p ** i * (1 - p) ** (n - i) for i in range(k + 1, n + 1))


def fmt(x):
    return repr(float(x))


def build(B):
    B.part("2", "What a network is")
    B.md(r"""
    # Part 2 — What a network is

    ## 2.1 Hosts, links, and packets

    * A **host** (or *end system*) is a computer that runs applications: a laptop, a phone, a server.
    * A **link** is a physical connection that carries bits between two devices: a cable, a fibre, or a radio channel.
    * A **node** is any device attached to links: a host, or a *packet switch*. A packet switch is
      a device that receives data on one link and forwards it on another; Part 4 distinguishes its two main kinds.
    * A **packet** is a bounded chunk of bytes sent as one unit. It has a **header** (control
      information: addresses, lengths, types) followed by a **payload** (the data being carried).

    ```
    [host A]===link===(packet switch)===link===(packet switch)===link===[host B]

    one packet:   +-----------+---------------------------+
                  |  header   |          payload          |
                  +-----------+---------------------------+
    ```

    A long message (a 1 GB file) is split into many packets, and each is forwarded independently.
    """)
    B.question("why", r"""Why split a 1 GB file into ~1500-byte packets instead of sending it as one giant unit?""",
               r"""
               * **Sharing:** a link carrying one giant unit is monopolised for its whole duration; with small packets
                 many conversations interleave on the same link.
               * **Error recovery:** a corrupted bit ruins only one small packet, which is resent, rather than the whole gigabyte.
               * **Buffering and pipelining:** a switch must store a whole unit before forwarding it (see §2.6), so
                 small packets need small buffers and let successive links work in parallel.

               *Misconception:* packets exist "because cables are short". Packetisation is about sharing and failure
               granularity, not distance.
               """)

    # ------------------------------------------------------------------ 2.2
    n, p, k = 35, 0.1, 10
    tail = binom_tail(n, p, k)
    B.md(r"""
    ## 2.2 Circuit switching vs packet switching

    **Circuit switching** (the classic telephone network) *reserves* a fixed share of capacity on
    every link along the path for the whole call. That share is guaranteed, but it is wasted whenever
    the user is silent.

    **Packet switching** (the Internet) reserves nothing. Packets from all users share each link on
    demand; a switch that receives a packet while the link is busy **stores** it in a buffer
    (a *queue*) and **forwards** it later. This is *statistical multiplexing*: it exploits the fact
    that users are rarely all active at once.

    Example: a 10 Mb/s link, where each user needs 1 Mb/s while active and is active 10% of the time.
    Circuit switching admits exactly 10 users. With packet switching and $n$ users, trouble (demand
    above 10 Mb/s) occurs only when more than 10 are active simultaneously:

    $$P(X > 10), \quad X \sim \mathrm{Binomial}(n, 0.1).$$
    """)
    B.exercise("2.2", "How rare is overload?",
               r"""
               Implement `prob_more_than(n, p, k)` $= P(X > k) = \sum_{i=k+1}^{n} \binom{n}{i} p^i (1-p)^{n-i}$.
               Write a helper `choose(n, i)` that computes $\binom{n}{i}$ in `double` with the product
               $\prod_{j=1}^{i} \frac{n - i + j}{j}$ (this avoids huge factorials). `std::pow` is in `<cmath>`.
               """,
               r"""
               namespace ex2_2 {
               double choose(int n, int i) { return 0.0; }                 // TODO
               double prob_more_than(int n, double p, int k) { return 0.0; } // TODO
               }
               """,
               r"""
               namespace ex2_2 {
               double choose(int n, int i) {
                   double c = 1.0;
                   for (int j = 1; j <= i; ++j) c = c * (n - i + j) / j;   // stays an integer at every step
                   return c;
               }
               double prob_more_than(int n, double p, int k) {
                   double total = 0.0;
                   for (int i = k + 1; i <= n; ++i)
                       total += choose(n, i) * std::pow(p, i) * std::pow(1.0 - p, n - i);
                   return total;
               }
               }
               """,
               fill(r"""
               {
                   CHECK_NEAR(ex2_2::choose(35, 11), @C@);
                   CHECK_NEAR(ex2_2::prob_more_than(10, 0.5, 5), @P1@);
                   double p35 = ex2_2::prob_more_than(35, 0.1, 10);
                   CHECK_NEAR(p35, @P2@);
                   std::cout << "P(overload) with 35 users = " << p35 << "\n";
               }
               """, C=fmt(comb(35, 11)), P1=fmt(binom_tail(10, 0.5, 5)), P2=fmt(tail)),
               fill(r"""
               With 35 users the link is overloaded only with probability ≈ @T@. Packet switching therefore serves
               **3.5×** as many users as circuit switching at nearly the same quality, and during that rare overload
               the excess is buffered rather than refused. The price is that delay is no longer guaranteed; that is
               the subject of §2.5.
               """, T=f"{tail:.4f}"))

    # ------------------------------------------------------------------ 2.3
    B.md(r"""
    ## 2.3 Bandwidth vs latency (and units)

    * **Bandwidth** (transmission rate) $R$ is the number of bits per second a link can push onto
      the wire: *how wide the pipe is*.
    * **Latency** is how long a bit takes to get from A to B: *how long the pipe is*.

    They are independent: a satellite link can have huge bandwidth *and* huge latency.

    **Units, the classic trap:**
    * `b` = bit and `B` = byte, so 100 **Mb/s** (megabits per second) = 12.5 **MB/s** (megabytes per second).
    * Data *rates* use decimal prefixes: k = 10³, M = 10⁶, G = 10⁹. Memory and file sizes are often
      binary: KiB = 1024 B, MiB = 1024² B.
    """)
    B.question("compute", r"""Your ISP sells "500 Mb/s". Ignoring overhead, how long does a 2 GB (2·10⁹ bytes) download take at best?""",
               f"""
               $\\dfrac{{2\\cdot10^9 \\cdot 8\\ \\text{{bits}}}}{{500\\cdot10^6\\ \\text{{bits/s}}}} = $ **{2e9 * 8 / 500e6:g} s**.

               Forgetting the factor 8 (bytes → bits) gives 4 s, which is 8× too optimistic. Always convert everything to bits
               *or* everything to bytes before dividing.
               """)

    # ------------------------------------------------------------------ 2.4
    L = 1500 * 8
    R = 1e9
    d = 3000e3
    s = 2e8
    B.md(r"""
    ## 2.4 Transmission delay and propagation delay

    Sending one packet of $L$ bits over one link of rate $R$ bits/s and length $d$ metres:

    * **Transmission delay** $d_\text{trans} = L / R$: the time to *push all $L$ bits onto the link*,
      one after another.
    * **Propagation delay** $d_\text{prop} = d / s$: the time for *one bit* to travel the length of the
      link at signal speed $s$. In copper and fibre $s \approx 2\cdot10^8$ m/s, about ⅔ of the speed of light.

    ```
    time ─►
    sender:    |<- L/R: first bit … last bit leave ->|
    receiver:              |<- d/s ->|<- L/R: first bit … last bit arrive ->|
    ```

    The two are easy to confuse. $L/R$ depends on the packet size and the link rate, not on distance;
    $d/s$ depends on distance, not on the packet or the rate.
    """)
    B.exercise("2.4", "Transmission and propagation delay",
               r"""
               Implement both functions (SI units: bits, bits/s, metres, metres/s; result in seconds).
               """,
               r"""
               namespace ex2_4 {
               double transmission_delay(double L_bits, double R_bps) { return 0.0; }   // TODO
               double propagation_delay(double d_m, double s_mps)     { return 0.0; }   // TODO
               }
               """,
               r"""
               namespace ex2_4 {
               double transmission_delay(double L_bits, double R_bps) { return L_bits / R_bps; }
               double propagation_delay(double d_m, double s_mps)     { return d_m / s_mps; }
               }
               """,
               fill(r"""
               {
                   // 1500-byte packet on a 1 Gb/s link that is 3000 km long
                   CHECK_NEAR(ex2_4::transmission_delay(1500 * 8, 1e9), @T@);
                   CHECK_NEAR(ex2_4::propagation_delay(3000e3, 2e8), @P@);
                   // same packet on a 10 Mb/s link
                   CHECK_NEAR(ex2_4::transmission_delay(1500 * 8, 10e6), @T2@);
               }
               """, T=fmt(L / R), P=fmt(d / s), T2=fmt(L / 10e6)),
               r"""
               Trivial formulas; the value of the exercise lies in the magnitudes. On a fast long-haul link propagation
               dominates by three orders of magnitude, whereas on a slow access link transmission can dominate.
               """, snippet_key="delays")
    B.question("compute", r"""For that 1500-byte packet over 3000 km of fibre at 1 Gb/s, which delay dominates, and by what factor?
    Would upgrading to 10 Gb/s help much?""",
               f"""
               $d_\\text{{trans}} = {L/R*1e6:g}\\ \\mu s$ and $d_\\text{{prop}} = {d/s*1e3:g}\\ \\text{{ms}}$: propagation is
               **{(d/s)/(L/R):g}×** larger. At 10 Gb/s, $d_\\text{{trans}}$ drops to {L/10e9*1e6:g} µs, but the total barely
               moves ({(L/R + d/s)*1e3:.4f} ms → {(L/10e9 + d/s)*1e3:.4f} ms).

               *Misconception:* "a faster link means lower latency". Bandwidth only shrinks $L/R$; nothing shrinks $d/s$ except
               moving the endpoints closer, which is why content is cached near users.
               """)

    # ------------------------------------------------------------------ 2.5
    N, Lq, Rq = 5, 1500 * 8, 100e6
    avgq = (N - 1) / 2 * Lq / Rq
    B.md(r"""
    ## 2.5 Queuing and processing delay

    Each switch along the path adds two more delays:

    * **Processing delay** $d_\text{proc}$: examining the header and choosing the output link
      (nanoseconds to microseconds in hardware).
    * **Queuing delay** $d_\text{queue}$: waiting in the output buffer while earlier packets are
      transmitted. It varies from packet to packet.

    $$d_\text{nodal} = d_\text{proc} + d_\text{queue} + d_\text{trans} + d_\text{prop}$$

    Queuing is governed by the **traffic intensity** $I = La/R$, where $a$ is the average arrival
    rate in packets/s. As $I \to 1$ the average queuing delay grows without bound, and for $I > 1$
    the queue grows forever. Buffers are finite, so a packet arriving at a full buffer is **dropped**:
    this is **packet loss**.

    A simple worst case is a *burst*: $N$ packets arrive at an empty link at the same instant.
    Packet $k$ (counting from 0) waits for the $k$ packets ahead of it, i.e. $k \cdot L/R$.
    """)
    B.exercise("2.5", "Average queuing delay of a burst",
               r"""
               Implement `avg_queuing_delay_burst(N, L_bits, R_bps)`: the average of $k \cdot L/R$ over $k = 0 \dots N-1$.
               Use a loop (do not look up a closed form yet).
               """,
               r"""
               namespace ex2_5 {
               double avg_queuing_delay_burst(int N, double L_bits, double R_bps) { return 0.0; }  // TODO
               }
               """,
               r"""
               namespace ex2_5 {
               double avg_queuing_delay_burst(int N, double L_bits, double R_bps) {
                   double total = 0.0;
                   for (int k = 0; k < N; ++k) total += k * L_bits / R_bps;   // packet k waits for k packets
                   return total / N;
               }
               }
               """,
               fill(r"""
               {
                   CHECK_NEAR(ex2_5::avg_queuing_delay_burst(1, 12000, 1e8), 0.0);
                   CHECK_NEAR(ex2_5::avg_queuing_delay_burst(@N@, @L@, @R@), @A@);
               }
               """, N=N, L=Lq, R=fmt(Rq), A=fmt(avgq)),
               fill(r"""
               Summing $k$ from 0 to $N-1$ gives $\frac{N(N-1)}{2}$, so the average is $\frac{N-1}{2}\cdot\frac{L}{R}$; for
               5 packets of 1500 B at 100 Mb/s that is @A@ µs. The first packet waits nothing and the last waits longest,
               so queuing delay differs from packet to packet even inside one burst. This variation is called **jitter**.
               """, A=f"{avgq*1e6:g}"))
    B.question("why", r"""A vendor proposes giant router buffers "so that no packet is ever dropped". Why is this a bad idea?
    Also compute $I$ for $L$ = 1500 B, $a$ = 8000 packets/s, $R$ = 100 Mb/s.""",
               f"""
               $I = \\dfrac{{12000 \\cdot 8000}}{{10^8}} = $ **{12000*8000/1e8:g}**, a busy link where queues form often.

               Huge buffers turn loss into **delay**: when $I$ approaches 1, a full giant buffer can hold hundreds of
               milliseconds of packets, so interactive traffic (calls, games) suffers. This is known as *bufferbloat*.
               Loss is also a useful **signal**: well-designed senders slow down when they notice loss, so hiding
               loss postpones their reaction. *Misconception:* "packet loss always means a broken link". Most loss on
               the Internet is simply full buffers.
               """)

    # ------------------------------------------------------------------ 2.6
    Ne, Le, Re, dpe = 3, 1500 * 8, 10e6, 1e-3
    e2e = Ne * (Le / Re + dpe)
    P = 4
    many = (Ne + P - 1) * Le / Re
    B.md(r"""
    ## 2.6 Store-and-forward over several links

    A packet switch must receive the **entire** packet before it forwards it: it has to read the
    whole header, and possibly check the entire packet for errors. This is **store-and-forward**. Over
    $N$ identical links with no queuing and no processing delay, one packet therefore takes

    $$d_\text{end-to-end} = N\left(\frac{L}{R} + d_\text{prop}\right).$$

    With $P$ packets sent back to back (ignore $d_\text{prop}$), the links work like a pipeline:

    ```
    time slot (each = L/R):   1    2    3    4    5    6
    link 1 (A -> S1):        p1   p2   p3   p4
    link 2 (S1 -> S2):            p1   p2   p3   p4
    link 3 (S2 -> B):                  p1   p2   p3   p4      total = (N + P - 1) · L/R
    ```
    """)
    B.exercise("2.6", "End-to-end delay",
               r"""
               * `e2e_one(N, L_bits, R_bps, dprop_per_link)`: one packet over $N$ links.
               * `e2e_many(P, N, L_bits, R_bps)`: $P$ back-to-back packets, ignoring propagation.
               """,
               r"""
               namespace ex2_6 {
               double e2e_one(int N, double L_bits, double R_bps, double dprop) { return 0.0; }  // TODO
               double e2e_many(int P, int N, double L_bits, double R_bps)       { return 0.0; }  // TODO
               }
               """,
               r"""
               namespace ex2_6 {
               double e2e_one(int N, double L_bits, double R_bps, double dprop) {
                   return N * (L_bits / R_bps + dprop);         // each hop: store fully, then send
               }
               double e2e_many(int P, int N, double L_bits, double R_bps) {
                   return (N + P - 1) * (L_bits / R_bps);        // pipeline: fill (N) + drain (P - 1)
               }
               }
               """,
               fill(r"""
               {
                   CHECK_NEAR(ex2_6::e2e_one(@N@, @L@, @R@, @D@), @E@);
                   CHECK_NEAR(ex2_6::e2e_many(@P@, @N@, @L@, @R@), @M@);
                   CHECK_NEAR(ex2_6::e2e_many(1, 1, @L@, @R@), @T@);   // one packet, one link = L/R
               }
               """, N=Ne, L=Le, R=fmt(Re), D=fmt(dpe), E=fmt(e2e), P=P, M=fmt(many), T=fmt(Le / Re)),
               fill(r"""
               For 3 links at 10 Mb/s with 1 ms of propagation each, one 1500 B packet takes @E@ ms. Four packets
               take $(3+4-1)\cdot 1.2$ ms = @M@ ms, **not** $4 \times 3 \times 1.2$ ms, because different links
               transmit different packets at the same time.
               """, E=f"{e2e*1e3:g}", M=f"{many*1e3:g}"))
    B.question("compute", r"""Instead of 4 packets of 1500 B, send the same 6000 B as ONE packet over the same 3 links
    (10 Mb/s, ignore propagation). How long does it take, and what does this say about packet size?""",
               f"""
               $3 \\cdot \\dfrac{{48000}}{{10^7}}$ = **{3*48000/1e7*1e3:g} ms**, versus {many*1e3:g} ms when split into 4 packets.
               Smaller packets let the links pipeline. They are not free, though: every packet carries a header, so
               tiny packets waste capacity on overhead. Real networks settle around 1500 B, a value you will meet again
               in Part 5.
               """)

    # ------------------------------------------------------------------ 2.7
    Rb, rtt = 1e9, 0.080
    bdp = Rb * rtt / 8
    W = 64 * 1024
    thr = W * 8 / rtt
    B.md(r"""
    ## 2.7 Round-trip time and the bandwidth-delay product

    The **round-trip time (RTT)** is the time from sending a message until its reply comes back:
    at least twice the one-way propagation delay, plus the transmission, queuing and processing delays.

    The **bandwidth-delay product** $\text{BDP} = R \cdot \text{RTT}$ is the amount of data that
    "fits in the pipe": the number of bits a sender must have sent, but not yet seen acknowledged,
    to keep the link busy while it waits for the first reply.

    ```
    sender ===[b][b][b][b][b][b][b][b][b][b]===> receiver     (bits in flight, one direction)
           <==========  acknowledgement returns  ============
           |<------------------ RTT ---------------------->|
    ```

    If a sender limits itself to $W$ unacknowledged bytes per RTT, its throughput is at most
    $W \cdot 8 / \text{RTT}$ bits/s, no matter how fast the link is.
    """)
    B.exercise("2.7", "BDP and window-limited throughput",
               r"""
               * `bdp_bytes(R_bps, rtt_s)`: the BDP in **bytes**.
               * `max_throughput_bps(window_bytes, rtt_s)`: the throughput cap of a window-limited sender.
               """,
               r"""
               namespace ex2_7 {
               double bdp_bytes(double R_bps, double rtt_s)                 { return 0.0; }  // TODO
               double max_throughput_bps(double window_bytes, double rtt_s) { return 0.0; }  // TODO
               }
               """,
               r"""
               namespace ex2_7 {
               double bdp_bytes(double R_bps, double rtt_s)                 { return R_bps * rtt_s / 8.0; }
               double max_throughput_bps(double window_bytes, double rtt_s) { return window_bytes * 8.0 / rtt_s; }
               }
               """,
               fill(r"""
               {
                   CHECK_NEAR(ex2_7::bdp_bytes(1e9, 0.080), @BDP@);
                   CHECK_NEAR(ex2_7::max_throughput_bps(64 * 1024, 0.080), @THR@);
                   std::cout << "64 KiB window over 80 ms RTT caps throughput at "
                             << ex2_7::max_throughput_bps(64 * 1024, 0.080) / 1e6 << " Mb/s\n";
               }
               """, BDP=fmt(bdp), THR=fmt(thr)),
               fill(r"""
               A 1 Gb/s path with 80 ms RTT holds @B@ MB in flight. A sender that allows only 64 KiB outstanding
               reaches just @T@ Mb/s, under 1% of the link. Protocols that wait for acknowledgements therefore need
               large windows on "long fat" paths.
               """, B=f"{bdp/1e6:g}", T=f"{thr/1e6:.2f}"))
    B.question("compute", r"""A transfer between Europe and the US uses a 10 Gb/s path with RTT 100 ms. How many bytes must be in flight
    to use the full rate? Would a single 1500-byte packet at a time come close?""",
               f"""
               $\\text{{BDP}} = 10^{{10}} \\cdot 0.1 / 8$ = **{1e10*0.1/8/1e6:g} MB**. One 1500-byte packet per RTT gives
               $1500\\cdot8/0.1$ = {1500*8/0.1/1e3:g} kb/s, a {1e10/(1500*8/0.1):,.0f}× shortfall. Long, fast paths need
               many packets outstanding at once.
               """)
    B.recap(
        ["Hosts and packet switches are connected by links; data travels in packets = header + payload.",
         "Packet switching shares links statistically (store-and-forward, queues); circuit switching reserves capacity.",
         "Four per-hop delays: processing, queuing, transmission $L/R$, and propagation $d/s$. Bandwidth only shrinks $L/R$.",
         "Queuing explodes as the traffic intensity $La/R \\to 1$; a full buffer means packet loss.",
         "BDP $= R\\cdot\\text{RTT}$ is the data needed in flight to fill a path; window/RTT caps throughput."],
        ["the difference between bandwidth and latency, with a concrete example;",
         "why a 10× faster link barely helps a transcontinental ping;",
         "why store-and-forward makes small packets pipeline better;",
         "how much data must be outstanding to fill a 1 Gb/s, 80 ms path."])
