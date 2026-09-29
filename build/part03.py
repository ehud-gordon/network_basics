from nb import fill, cpp_bytes, hexdump_py, be16


def toy_header(tag: str, payload: bytes) -> bytes:
    return bytes([ord(tag)]) + be16(len(payload)) + payload


def toy_encapsulate(msg: bytes) -> bytes:
    seg = toy_header("T", msg)
    pkt = toy_header("N", seg)
    return toy_header("L", pkt)


def build(B):
    B.part("3", "Layering")
    B.md(r"""
    # Part 3 — Layering

    ## 3.1 Why layers exist

    A **protocol** is an agreement on the *format* of messages, their *order*, and the *actions*
    taken on sending or receiving them. Networking needs dozens of protocols, and **layering** keeps
    them manageable. Each layer:

    * offers a **service** to the layer above (e.g. "deliver these bytes to that host");
    * uses only the service of the layer below, without knowing how that layer works;
    * talks to its **peer**, the same layer on the other machine, through its own header.

    ```
    host A                                   host B
    layer n   <------ peer protocol ------>  layer n
       | uses the service of the layer below    ^
       v                                        |
    layer n-1 <------ peer protocol ------>  layer n-1
    ```

    Postal analogy: you write a letter (application), the post office routes envelopes between cities
    (network), and trucks and planes move sacks (link and physical). The letter's author never sees a truck.
    """)
    B.question("why", r"""Give one major benefit and one real cost of layering.""",
               r"""
               **Benefit, modularity:** any layer can be replaced without touching the others. The same web browser
               works over Wi-Fi, Ethernet, or 5G because only the lowest layers differ.

               **Costs:** (1) *overhead*: every layer adds its own header bytes; (2) *information hiding*: a layer
               cannot see what it might need. A web browser does not know the link is a lossy radio, and the radio does
               not know which bytes are urgent. (3) Some functions get *duplicated* at several layers (error detection
               exists at layers 2 and 4). *Misconception:* layers are a law of nature; in fact they are an engineering
               convention that real systems sometimes bend for performance.
               """)

    # ------------------------------------------------------------------ 3.2
    B.md(r"""
    ## 3.2 The OSI 7-layer model

    The **OSI** (Open Systems Interconnection) reference model names seven layers. Engineers still
    say "layer 2" or "an L7 load balancer" using this numbering. The **PDU** (protocol data unit)
    is the name of a layer's chunk of data.

    | # | Layer | One-line job | PDU | Example protocols |
    |---|---|---|---|---|
    | 7 | Application | the service a program wants | data (message) | HTTP (fetch web pages), DNS (look up names) |
    | 6 | Presentation | how data is represented: encoding, compression, encryption | data | UTF-8, JPEG |
    | 5 | Session | managing a long dialogue: open, checkpoint, resume | data | RPC session control |
    | 4 | Transport | deliver data between **programs** on two hosts | segment (TCP) / datagram (UDP) | TCP (reliable byte stream), UDP (single messages) |
    | 3 | Network | deliver packets between **hosts** across many networks | packet | IP (Internet Protocol) |
    | 2 | Data link | deliver frames between **neighbours** on one link | frame | Ethernet (wired), Wi-Fi |
    | 1 | Physical | turn bits into signals on a medium | bits | copper, fibre, radio signalling |

    Mnemonic, bottom-up: **P**lease **D**o **N**ot **T**hrow **S**ausage **P**izza **A**way.

    Each layer has its own address:
    * a **MAC address** (L2) is a 48-bit identifier of a network interface, meaningful on the local link only;
    * an **IP address** (L3) is a 32-bit identifier of a host's interface, meaningful across the Internet;
    * a **port** (L4) is a 16-bit number identifying which program on a host the data is for.
    """)
    B.question("concept", r"""At which OSI layer does each live: (a) a MAC address, (b) an IP address, (c) a port number?
    And what is the PDU called at layers 2, 3, and 4?""",
               r"""
               (a) **L2** Data link, (b) **L3** Network, (c) **L4** Transport. PDUs: L2 **frame**, L3 **packet**,
               L4 **segment** (TCP) or **datagram** (UDP).

               The layers answer successive questions: *which neighbour on this wire?* (MAC), *which host on the
               Internet?* (IP), *which program on that host?* (port). *Misconception:* people say "packet" for every
               layer. In an interview, "frame" vs "packet" vs "segment" signals which header you are talking about.
               """)

    # ------------------------------------------------------------------ 3.3
    B.md(r"""
    ## 3.3 The TCP/IP model and how it maps onto OSI

    The Internet was not built from OSI; it follows the simpler **TCP/IP model** with four layers:

    ```
         OSI                      TCP/IP (Internet) model
    7  Application   ┐
    6  Presentation  ├───────►  Application   HTTP, DNS    (programs handle 5-7 themselves)
    5  Session       ┘
    4  Transport     ────────►  Transport     TCP, UDP
    3  Network       ────────►  Internet      IP
    2  Data link     ┐
    1  Physical      ┘───────►  Link          Ethernet, Wi-Fi (framing + signalling)
    ```

    Many textbooks use a 5-layer hybrid (keeping Physical separate). OSI is the *vocabulary*;
    TCP/IP is what actually runs. An operating system implements Transport, Internet and part of Link;
    the NIC hardware (Part 4) implements Physical and part of Link; applications implement the rest.
    """)
    B.question("why", r"""OSI's Session and Presentation layers have no separate TCP/IP layer. Where did their jobs go?""",
               r"""
               Into the **application** and the libraries it links: character encoding, compression, serialization
               formats (JSON, Protobuf), and encryption libraries all run inside the application process. Session-like
               behaviour (logins, resuming a download) is part of the application protocol itself. *Misconception:*
               "those layers do not exist". The functions exist; they simply are not a separate, standardised layer in the
               OS network stack.
               """)

    # ------------------------------------------------------------------ 3.4
    msg, tcp, ip, eth, fcs = 100, 20, 20, 14, 4
    frame = msg + tcp + ip + eth + fcs
    B.md(r"""
    ## 3.4 Encapsulation and decapsulation

    Going **down** the stack, each layer treats everything it receives from above as an opaque
    **payload** and prepends its own **header**. The link layer also appends a **trailer** (an error
    check). This is **encapsulation**:

    ```
    Application                               [       data        ]
    Transport                       [TCP hdr ][       data        ]              <- segment
    Network               [IP hdr  ][TCP hdr ][       data        ]              <- packet
    Link        [Eth hdr ][IP hdr  ][TCP hdr ][       data        ][ trailer ]   <- frame
    Physical    0110100101110001011010 ... bits as signals on the medium
    ```

    Going **up** on the receiver, each layer checks and strips its own header, then hands the
    payload to the layer above: **decapsulation**. Every header contains a field naming the protocol
    of its payload (for example "this IP packet carries TCP"), so the receiver knows which upper-layer
    code to call. Dispatching on that field is **demultiplexing**.
    """)
    B.question("compute", fill(r"""A @M@-byte application message goes out over TCP (20-byte header), IP (20-byte header), and
    Ethernet (14-byte header + 4-byte trailer). How big is the frame, and what fraction of it is application data?""", M=msg),
               f"""
               {msg} + {tcp} + {ip} + {eth} + {fcs} = **{frame} bytes**; efficiency = {msg}/{frame} = **{msg/frame:.1%}**.

               Headers are a fixed cost per packet, so small messages are inefficient. With a 1460-byte message the
               efficiency is {1460/(1460+tcp+ip+eth+fcs):.1%}. This is one reason chatty protocols batch small writes.
               """)
    B.question("why", r"""Why must each header carry a "type of my payload" field? Couldn't the receiver just guess from the bytes?""",
               r"""
               The payload is just bytes, and the same bytes could be a valid start of many different protocols, so guessing
               is ambiguous and fragile. An IP layer may receive TCP, UDP or control messages; Ethernet may carry IPv4,
               IPv6 or other protocols. An explicit type field makes demultiplexing a simple table lookup and keeps the
               layers independent, since the lower layer never parses the upper header.
               """)

    B.md(r"""
    ### A toy protocol stack

    To practise, use a toy format in which **every** layer's header is 3 bytes:

    ```
    offset:  0          1   2
            +----------+--------------------+
            |  tag     |  payload length    |   length = number of bytes AFTER the header,
            | (1 byte) | (uint16, big-end.) |            in network byte order
            +----------+--------------------+
    tags:  'T' transport     'N' network     'L' link
    ```

    Your code needs the byte-order helpers from Part 1; they are provided in the next cell.
    """)
    B.provided("lib3", [("1.6", "be")])
    enc = toy_encapsulate(b"hi")
    B.exercise("3.4a", "Add and strip one toy header",
               r"""
               * `add_header(tag, payload)`: return `tag`, then the 2-byte big-endian length, then the payload.
               * `strip_header(pdu, tag, payload_out)`: if `pdu` is at least 3 bytes long, starts with `tag`, **and** its
                 length field equals the number of bytes that follow, copy those bytes into `payload_out` and return `true`;
                 otherwise return `false`.

               `std::vector<uint8_t>` is the standard growable byte buffer: `v.push_back(b)`, `v.size()`,
               `v.insert(v.end(), other.begin(), other.end())` appends another vector, and `v.data()` gives a
               `uint8_t*` to its bytes.
               """,
               r"""
               namespace ex3_4a {
               std::vector<uint8_t> add_header(uint8_t tag, const std::vector<uint8_t>& payload) {
                   // TODO (use lib3::write_be16)
                   return {};
               }
               bool strip_header(const std::vector<uint8_t>& pdu, uint8_t tag, std::vector<uint8_t>& payload_out) {
                   // TODO (use lib3::read_be16)
                   return false;
               }
               }
               """,
               r"""
               namespace ex3_4a {
               std::vector<uint8_t> add_header(uint8_t tag, const std::vector<uint8_t>& payload) {
                   std::vector<uint8_t> out(3);                         // room for the header
                   out[0] = tag;
                   lib3::write_be16(&out[1], uint16_t(payload.size()));
                   out.insert(out.end(), payload.begin(), payload.end());
                   return out;
               }
               bool strip_header(const std::vector<uint8_t>& pdu, uint8_t tag, std::vector<uint8_t>& payload_out) {
                   if (pdu.size() < 3 || pdu[0] != tag) return false;
                   uint16_t len = lib3::read_be16(&pdu[1]);
                   if (len != pdu.size() - 3) return false;            // truncated or trailing garbage
                   payload_out.assign(pdu.begin() + 3, pdu.end());
                   return true;
               }
               }
               """,
               r"""
               {
                   std::vector<uint8_t> payload = {'h', 'i'};
                   auto t = ex3_4a::add_header('T', payload);
                   CHECK_EQ(t, (std::vector<uint8_t>{'T', 0x00, 0x02, 'h', 'i'}));

                   std::vector<uint8_t> back;
                   CHECK(ex3_4a::strip_header(t, 'T', back));
                   CHECK_EQ(back, payload);
                   CHECK(!ex3_4a::strip_header(t, 'N', back));                                  // wrong tag
                   CHECK(!ex3_4a::strip_header(std::vector<uint8_t>{'T', 0x00, 0x05, 'h'}, 'T', back)); // truncated
                   CHECK(!ex3_4a::strip_header(std::vector<uint8_t>{'T', 0x00}, 'T', back));   // too short for a header
               }
               """,
               r"""
               Validating the length field against the real size is not pedantry: a receiver that trusts a length field
               blindly reads past the end of its buffer. That is exactly how famous memory-disclosure bugs in network
               code happen. Always check that a header fits **before** reading it, and that its length claims are consistent.
               """, snippet_key="toy_hdr")
    B.provided("lib3b", [("3.4a", "toy_hdr")])
    B.exercise("3.4b", "Encapsulate and decapsulate a message",
               fill(r"""
               * `encapsulate(msg)`: wrap the message's bytes with `'T'`, then `'N'`, then `'L'` (outermost).
               * `decapsulate(frame)`: undo it, strictly in the order L, N, T, and return the message.

               `decapsulate` returns `std::optional<std::string>` (from `<optional>`): an object that holds either a value
               or nothing. Return `std::nullopt` for "nothing" (any layer failed) or the string itself on success. The caller
               tests it with `if (r)` and reads it with `*r`. Use `lib3b::add_header` / `lib3b::strip_header` (PROVIDED above).

               For `"hi"` the frame is @N@ bytes:
               ```
               @DUMP@
               ```
               """, N=len(enc), DUMP=hexdump_py(enc)),
               r"""
               namespace ex3_4b {
               std::vector<uint8_t> encapsulate(const std::string& msg) {
                   // TODO
                   return {};
               }
               std::optional<std::string> decapsulate(const std::vector<uint8_t>& frame) {
                   // TODO
                   return std::nullopt;
               }
               }
               """,
               r"""
               namespace ex3_4b {
               std::vector<uint8_t> encapsulate(const std::string& msg) {
                   std::vector<uint8_t> data(msg.begin(), msg.end());      // application data as bytes
                   auto segment = lib3b::add_header('T', data);           // transport
                   auto packet  = lib3b::add_header('N', segment);        // network
                   return lib3b::add_header('L', packet);                 // link (outermost)
               }
               std::optional<std::string> decapsulate(const std::vector<uint8_t>& frame) {
                   std::vector<uint8_t> packet, segment, data;
                   if (!lib3b::strip_header(frame, 'L', packet))   return std::nullopt;
                   if (!lib3b::strip_header(packet, 'N', segment)) return std::nullopt;
                   if (!lib3b::strip_header(segment, 'T', data))   return std::nullopt;
                   return std::string(data.begin(), data.end());
               }
               }
               """,
               fill(r"""
               {
                   auto f = ex3_4b::encapsulate("hi");
                   hexdump(f);
                   CHECK_EQ(f, (std::vector<uint8_t>{
               @BYTES@
                   }));
                   auto m = ex3_4b::decapsulate(f);
                   CHECK(m.has_value());
                   CHECK_EQ(m.value_or("<nothing>"), "hi");

                   auto big = ex3_4b::encapsulate(std::string(300, 'x'));
                   CHECK_EQ(big.size(), 309u);
                   CHECK_EQ(ex3_4b::decapsulate(big).value_or("<nothing>").size(), 300u);

                   auto bad = f;
                   if (bad.size() > 3) bad[3] = 'X';                        // corrupt the network tag
                   CHECK(!ex3_4b::decapsulate(bad).has_value());
               }
               """, BYTES=cpp_bytes(enc, indent="        ")),
               r"""
               The byte layout makes the nesting visible: `L 00 08 | N 00 05 | T 00 02 | h i`. Each length counts
               everything **inside** it, including inner headers. The order matters: decapsulation strictly reverses
               encapsulation, and a failure at any layer discards the whole frame. That is what real stacks do with a
               malformed header.

               (The corruption test in the test cell guards with `if (bad.size() > 3)` so that the *unsolved* stub,
               which returns an empty vector, cannot index out of bounds.)
               """)
    B.recap(
        ["A protocol defines message format, order, and actions; layers each offer a service upward and talk to their peer.",
         "OSI: Physical, Data link, Network, Transport, Session, Presentation, Application (PDUs: bits, frame, packet, segment/datagram, data).",
         "TCP/IP folds OSI 5–7 into Application and 1–2 into Link.",
         "Encapsulation prepends a header per layer (plus a link trailer); decapsulation strips them in reverse.",
         "A 'next protocol' field in each header drives demultiplexing."],
        ["what lives at L2, L3 and L4, and each layer's PDU name;",
         "how the OSI and TCP/IP models map onto each other;",
         "the byte overhead of headers for a small message;",
         "why a parser must check a length field before trusting it."])
