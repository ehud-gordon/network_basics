from nb import fill

FD_HELPERS = r"""
// RAII owner of a file descriptor: the destructor closes it on EVERY path out of a scope
// (normal return, early return, exception). Copying is forbidden so there is exactly one owner.
struct Fd {
    int fd = -1;
    explicit Fd(int f) : fd(f) {}
    ~Fd() { if (fd >= 0) ::close(fd); }
    Fd(const Fd&) = delete;
    Fd& operator=(const Fd&) = delete;
};

// The socket API takes a generic sockaddr*; this cast lets us pass our IPv4 sockaddr_in.
sockaddr* sa(sockaddr_in* a) { return reinterpret_cast<sockaddr*>(a); }
"""


def build(B):
    B.part("9", "Sockets in practice (loopback only)")
    B.md(r"""
    # Part 9 — Sockets in practice (loopback only)

    Everything so far has been simulated. Now you use your operating system's real TCP/IP stack.
    All traffic stays on **loopback** (`127.0.0.1`): packets never leave the machine, no special
    privileges are needed, and nothing depends on an external network.

    ## 9.1 Sockets, file descriptors, and addresses

    The kernel implements UDP, TCP and IP; a program uses them through **system calls** on a
    **socket**. A socket is referred to by a **file descriptor** (fd), a small non-negative `int`
    handle, like an open file. Failing calls return `-1` and set **`errno`**, a per-thread error code
    (`std::strerror(errno)` gives its text).

    | call | purpose |
    |---|---|
    | `socket(AF_INET, SOCK_DGRAM or SOCK_STREAM, 0)` | create a UDP or TCP socket → fd |
    | `bind(fd, addr, len)` | attach a local IP and port; **port 0 = "kernel, pick a free one"** |
    | `getsockname(fd, addr, &len)` | read back the local address (e.g. the chosen port) |
    | `setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv)` | make blocking receives give up after `tv` |
    | `close(fd)` | release the socket |

    An IPv4 address is passed as `sockaddr_in` with `sin_family = AF_INET`, and `sin_port` and
    `sin_addr.s_addr` in **network byte order** (`htons`, `htonl`, §1.7). `INADDR_LOOPBACK` is 127.0.0.1
    as a host-order value. **`SO_RCVTIMEO`** takes a `timeval {tv_sec, tv_usec}`; a receive that times
    out returns `-1` with `errno` = `EAGAIN`/`EWOULDBLOCK`. Every receiving socket in this part gets
    a ~2 s timeout, so that no bug can hang the notebook.

    The cell below gives two helpers: `Fd`, which closes its descriptor automatically when it goes out
    of scope (the C++ idiom called **RAII**, resource acquisition is initialisation), and `sa`, a cast helper.
    """)
    B.provided("lib9", [("given", FD_HELPERS)])
    B.exercise("9.1", "Address, port and timeout helpers",
               r"""
               * `make_loopback_addr(port)`: a zero-initialised `sockaddr_in` for 127.0.0.1:`port`.
               * `local_port(fd)`: the local port via `getsockname`, or `-1` on error.
               * `set_recv_timeout(fd, ms)`: set `SO_RCVTIMEO`; return `true` on success.
               """,
               r"""
               namespace ex9_1 {
               sockaddr_in make_loopback_addr(uint16_t port) { return {}; }   // TODO
               int local_port(int fd)                        { return -1; }   // TODO
               bool set_recv_timeout(int fd, int ms)         { return false; }// TODO
               }
               """,
               r"""
               namespace ex9_1 {
               sockaddr_in make_loopback_addr(uint16_t port) {
                   sockaddr_in a{};                               // zero all fields (incl. padding)
                   a.sin_family = AF_INET;
                   a.sin_port = htons(port);                      // network byte order!
                   a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);    // 127.0.0.1, network byte order
                   return a;
               }
               int local_port(int fd) {
                   sockaddr_in a{};
                   socklen_t len = sizeof a;
                   if (getsockname(fd, lib9::sa(&a), &len) != 0) return -1;
                   return ntohs(a.sin_port);
               }
               bool set_recv_timeout(int fd, int ms) {
                   timeval tv{};
                   tv.tv_sec = ms / 1000;
                   tv.tv_usec = (ms % 1000) * 1000;
                   return setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv) == 0;
               }
               }
               """,
               r"""
               {
                   auto a = ex9_1::make_loopback_addr(8080);
                   CHECK_EQ(int(a.sin_family), AF_INET);
                   CHECK_EQ(a.sin_port, htons(8080));
                   CHECK_EQ(ntohl(a.sin_addr.s_addr), 0x7F000001u);

                   lib9::Fd s(socket(AF_INET, SOCK_DGRAM, 0));
                   auto any = ex9_1::make_loopback_addr(0);
                   CHECK_EQ(bind(s.fd, lib9::sa(&any), sizeof any), 0);
                   int port = ex9_1::local_port(s.fd);
                   std::cout << "the kernel assigned port " << port << "\n";
                   CHECK(port > 0);

                   CHECK(ex9_1::set_recv_timeout(s.fd, 200));
                   timeval tv{};
                   socklen_t tl = sizeof tv;
                   getsockopt(s.fd, SOL_SOCKET, SO_RCVTIMEO, &tv, &tl);        // read the option back
                   long us = long(tv.tv_sec) * 1000000 + long(tv.tv_usec);
                   bool timeout_set = (us >= 150000 && us <= 250000);
                   CHECK(timeout_set);
                   if (timeout_set) {                     // only then is recv() guaranteed not to block forever
                       char b[16];
                       auto t0 = std::chrono::steady_clock::now();
                       ssize_t n = recv(s.fd, b, sizeof b, 0);                 // nobody sends: must time out
                       int err = errno;
                       double waited = std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();
                       CHECK(n < 0 && (err == EAGAIN || err == EWOULDBLOCK));
                       std::cout << "recv() gave up after " << std::setprecision(2) << waited << std::setprecision(6) << " s: "
                                 << std::strerror(err) << "\n";
                   }
               }
               """,
               r"""
               `sockaddr_in a{}` zeroes the structure, including the `sin_zero` padding, which some systems check. Forgetting
               `htons` on the port is the classic socket bug: `a.sin_port = 8080` silently binds port 36895 (0x1F90 byte-swapped
               is 0x901F) on a little-endian machine. `getsockname` is the only way to learn which port the kernel chose for port 0.
               """, snippet_key="sock_helpers")
    B.question("why", r"""Why do all our servers bind to port 0 instead of a fixed port such as 8080?""",
               r"""
               A fixed port may already be in use (by another program, another notebook, or a previous run still in `TIME_WAIT`),
               and `bind` would then fail with `EADDRINUSE`. Port 0 asks the kernel for **any free port**, which always
               works; `getsockname` then tells us which one we got so the client can connect to it. Real servers use fixed,
               well-known ports so that clients can find them; tests use port 0 to avoid conflicts.
               """)

    # ------------------------------------------------------------------ 9.2 UDP echo
    B.md(r"""
    ## 9.2 UDP echo in one process

    ```
    server                                client
    socket(SOCK_DGRAM)                    socket(SOCK_DGRAM)
    bind(127.0.0.1:0)
                                          sendto(data, server address)
                                            └─ the kernel auto-binds the client to an EPHEMERAL port
    recvfrom(buf, &sender) -> data + the sender's address
    sendto(data, sender)                  recv(buf) -> the echo
    close()                               close()
    ```

    `sendto(fd, data, len, 0, addr, addrlen)` sends one datagram; `recvfrom(fd, buf, cap, 0, addr, &addrlen)`
    receives one and fills in who sent it. Both return the number of bytes, or `-1` on error.
    """)
    B.provided("lib9b", [("9.1", "sock_helpers")])
    B.exercise("9.2", "A UDP echo round trip",
               r"""
               Implement `udp_echo_once(msg, port_seen_by_server, client_local_port)` following the diagram, in one thread,
               with two `lib9::Fd` sockets. Set a 2000 ms receive timeout on both. Record the client's port as the server saw
               it (from `recvfrom`) and as the client sees it (`local_port` after the first `sendto`). Return the echoed
               string, or `""` on any failure.
               """,
               r"""
               namespace ex9_2 {
               std::string udp_echo_once(const std::string& msg, int& port_seen_by_server, int& client_local_port) {
                   port_seen_by_server = -1;
                   client_local_port = -1;
                   // TODO
                   return "";
               }
               }
               """,
               r"""
               namespace ex9_2 {
               std::string udp_echo_once(const std::string& msg, int& port_seen_by_server, int& client_local_port) {
                   port_seen_by_server = -1;
                   client_local_port = -1;
                   lib9::Fd server(socket(AF_INET, SOCK_DGRAM, 0));
                   lib9::Fd client(socket(AF_INET, SOCK_DGRAM, 0));
                   if (server.fd < 0 || client.fd < 0) return "";

                   sockaddr_in addr = lib9b::make_loopback_addr(0);
                   if (bind(server.fd, lib9::sa(&addr), sizeof addr) != 0) return "";
                   addr = lib9b::make_loopback_addr(uint16_t(lib9b::local_port(server.fd)));   // real server address
                   lib9b::set_recv_timeout(server.fd, 2000);
                   lib9b::set_recv_timeout(client.fd, 2000);

                   if (sendto(client.fd, msg.data(), msg.size(), 0, lib9::sa(&addr), sizeof addr) < 0) return "";
                   client_local_port = lib9b::local_port(client.fd);         // assigned by that first sendto

                   char buf[1500];
                   sockaddr_in peer{};
                   socklen_t plen = sizeof peer;
                   ssize_t n = recvfrom(server.fd, buf, sizeof buf, 0, lib9::sa(&peer), &plen);
                   if (n < 0) return "";
                   port_seen_by_server = ntohs(peer.sin_port);
                   sendto(server.fd, buf, size_t(n), 0, lib9::sa(&peer), plen);   // echo to whoever sent it

                   n = recv(client.fd, buf, sizeof buf, 0);
                   if (n < 0) return "";
                   return std::string(buf, size_t(n));
               }                                                           // both fds closed here
               }
               """,
               r"""
               {
                   int seen = -1, local = -1;
                   std::string r = ex9_2::udp_echo_once("ping over UDP", seen, local);
                   std::cout << "echo: \"" << r << "\"  client port (server's view) " << seen
                             << ", (client's view) " << local << "\n";
                   CHECK_EQ(r, "ping over UDP");
                   CHECK(seen == local && local >= 1024);        // an ephemeral port, seen identically by both
               }
               """,
               r"""
               A single thread suffices because `sendto` never waits for the receiver: the datagram is queued in the server socket's
               receive buffer until `recvfrom` collects it. The client never called `bind`, yet it has a port: the kernel assigned
               an **ephemeral** one at the first `sendto`, and the server learned it from the datagram's source port, the same
               5-tuple mechanism as §8.1.
               """)
    B.question("why", r"""What happens if the client's datagram is lost (impossible on loopback, common on Wi-Fi) in the code above?
    What would a real UDP application need to add?""",
               r"""
               `recvfrom` on the server times out after 2 s and the function returns `""`. Without the timeout it would block
               **forever**, because UDP never tells you that a datagram was lost. A real application needs its own timeout and
               retry logic (DNS resolvers resend after about 1 s), identifiers to match replies with requests (the DNS ID field),
               and must tolerate duplicates. *Misconception:* "`sendto` succeeded, so it was delivered". Success only means
               the datagram was handed to the local kernel.
               """)

    # ------------------------------------------------------------------ 9.3 TCP echo
    B.md(r"""
    ## 9.3 A TCP client and server with `std::thread`

    ```
    server                                        client
    socket(SOCK_STREAM)
    bind(127.0.0.1:0)
    listen(fd, backlog)    <- LISTEN: the kernel now completes handshakes on its own
    accept(fd, &peer)  ·························  connect(server address)    <- 3-way handshake
      └─ returns a NEW fd for this one connection
    recv / send        <=======================>  send / recv
    close()                                       close()                    <- FIN exchange
    ```

    The **listening** socket only produces new connections; each `accept` returns a **connected**
    socket for one client. Both sides block, so they must run **concurrently**:
    `std::thread t([&] { ... });` runs the lambda in a new thread (`[&]` lets it use the enclosing
    function's local variables by reference), and `t.join()` waits for it to finish. A `std::thread`
    destroyed without `join()` **terminates the whole program**, so always join before returning.

    Send with `send(fd, data, len, MSG_NOSIGNAL)`: without `MSG_NOSIGNAL`, writing to a connection the
    peer has closed raises the `SIGPIPE` signal, which kills the process (the setup cell also ignores it).
    Setting `SO_RCVTIMEO` on the listening socket makes `accept` give up too.
    """)
    B.exercise("9.3", "TCP echo over loopback",
               r"""
               Implement `tcp_echo(msg, port_seen_by_server, client_local_port)`:
               1. Create the listening socket, bind to port 0, `listen(fd, 1)`, set a 2000 ms timeout, and compute the server
                  address. Do this **before** starting the thread, so that the client can never connect too early.
               2. Server thread: `accept` (record the peer's port), set a timeout on the new fd, `recv` once, `send` it back.
               3. Main thread (client): `connect`, record `local_port`, `send` the message, then `recv` in a loop until
                  `msg.size()` bytes have arrived or `recv` returns ≤ 0.
               4. `join` the thread, then return what the client received.
               """,
               r"""
               namespace ex9_3 {
               std::string tcp_echo(const std::string& msg, int& port_seen_by_server, int& client_local_port) {
                   port_seen_by_server = -1;
                   client_local_port = -1;
                   // TODO
                   return "";
               }
               }
               """,
               r"""
               namespace ex9_3 {
               std::string tcp_echo(const std::string& msg, int& port_seen_by_server, int& client_local_port) {
                   port_seen_by_server = -1;
                   client_local_port = -1;
                   lib9::Fd listener(socket(AF_INET, SOCK_STREAM, 0));
                   if (listener.fd < 0) return "";
                   sockaddr_in addr = lib9b::make_loopback_addr(0);
                   if (bind(listener.fd, lib9::sa(&addr), sizeof addr) != 0) return "";
                   if (listen(listener.fd, 1) != 0) return "";
                   lib9b::set_recv_timeout(listener.fd, 2000);                   // accept() gives up after 2 s
                   addr = lib9b::make_loopback_addr(uint16_t(lib9b::local_port(listener.fd)));

                   std::thread server([&] {
                       sockaddr_in peer{};
                       socklen_t plen = sizeof peer;
                       lib9::Fd conn(accept(listener.fd, lib9::sa(&peer), &plen));   // NEW socket per connection
                       if (conn.fd < 0) return;
                       port_seen_by_server = ntohs(peer.sin_port);
                       lib9b::set_recv_timeout(conn.fd, 2000);
                       char buf[256];
                       ssize_t n = recv(conn.fd, buf, sizeof buf, 0);
                       if (n > 0) send(conn.fd, buf, size_t(n), MSG_NOSIGNAL);      // echo
                   });                                                               // conn closed here

                   std::string reply;
                   {
                       lib9::Fd client(socket(AF_INET, SOCK_STREAM, 0));
                       lib9b::set_recv_timeout(client.fd, 2000);
                       if (client.fd >= 0 && connect(client.fd, lib9::sa(&addr), sizeof addr) == 0) {
                           client_local_port = lib9b::local_port(client.fd);
                           send(client.fd, msg.data(), msg.size(), MSG_NOSIGNAL);
                           char buf[256];
                           while (reply.size() < msg.size()) {       // the echo may arrive in pieces
                               ssize_t n = recv(client.fd, buf, sizeof buf, 0);
                               if (n <= 0) break;                    // closed, error, or timeout
                               reply.append(buf, size_t(n));
                           }
                       }
                   }                                                 // client closed here
                   server.join();                                    // joined on every path
                   return reply;
               }
               }
               """,
               r"""
               {
                   int seen = -1, local = -1;
                   std::string r = ex9_3::tcp_echo("hello over TCP", seen, local);
                   std::cout << "echo: \"" << r << "\"  client port (server's view) " << seen
                             << ", (client's view) " << local << "\n";
                   CHECK_EQ(r, "hello over TCP");
                   CHECK(seen == local && local >= 1024);

                   int seen2 = -1, local2 = -1;
                   ex9_3::tcp_echo("again", seen2, local2);
                   std::cout << "second run used client port " << local2 << "\n";
                   CHECK(local2 >= 1024);                        // another ephemeral port (usually a different one)
               }
               """,
               r"""
               Creating the listening socket *before* starting the thread removes the race: once `listen` has returned, the kernel
               completes the handshake of an incoming `connect` and queues the connection even if `accept` has not been called yet.
               The timeouts guarantee termination: if `connect` fails, `accept` gives up after 2 s, the thread ends, and `join`
               returns. Each run usually gets a different ephemeral port. The kernel may reuse a port number only for a *different*
               5-tuple (here, a different server port), because the old connection is still in `TIME_WAIT` on the side that
               closed first (§8.7).
               """, snippet_key="tcp_echo")
    B.question("concept", r"""In `tcp_echo`, how many file descriptors does the server side use, and which 5-tuple does the accepted one
    represent? Which socket would a second client's SYN reach?""",
               r"""
               Two: the **listening** fd (local 127.0.0.1:P, no remote) and the **connected** fd returned by `accept`, representing
               (TCP, 127.0.0.1, client port, 127.0.0.1, P). A second client's SYN matches no existing connection's 5-tuple, so it
               reaches the **listening** socket and would create a third fd at the next `accept`: exactly the demultiplexing
               rules you implemented in §8.1.
               """)

    # ------------------------------------------------------------------ 9.4 no message boundaries
    B.md(r"""
    ## 9.4 TCP does not preserve message boundaries

    TCP delivers a **byte stream** (§8.4). The kernel may merge several `send` calls into one segment,
    split one `send` across segments, and `recv` returns **whatever bytes are available**, up to the
    buffer size. Message boundaries are simply not part of the service.
    """)
    B.question("predict", r"""A client calls `send("hello")`, then `send("world")`. The server sleeps 200 ms, then calls
    `recv(fd, buf, 100, 0)` once. What does that `recv` most likely return?""",
               r"""
               Most likely **all 10 bytes, `helloworld`**, in one `recv`: both writes are already sitting in the server's receive
               buffer, and `recv` hands over everything available. It *could* return 5 bytes, or even 3. TCP promises only the
               **order** of bytes, never how they are grouped. *Misconception:* "one send = one recv". Code that assumes this
               works in testing and breaks under load. Run the demo below.
               """)
    B.code(r"""
    namespace demo9_4 {
    // GIVEN demo: two send() calls on the client, then the server reads with a 100-byte buffer.
    std::vector<std::string> two_sends() {
        std::vector<std::string> pieces;               // what each server recv() returned
        lib9::Fd listener(socket(AF_INET, SOCK_STREAM, 0));
        sockaddr_in addr = lib9b::make_loopback_addr(0);
        if (listener.fd < 0 || bind(listener.fd, lib9::sa(&addr), sizeof addr) != 0 || listen(listener.fd, 1) != 0)
            return pieces;
        lib9b::set_recv_timeout(listener.fd, 2000);
        addr = lib9b::make_loopback_addr(uint16_t(lib9b::local_port(listener.fd)));

        std::thread server([&] {
            lib9::Fd conn(accept(listener.fd, nullptr, nullptr));
            if (conn.fd < 0) return;
            lib9b::set_recv_timeout(conn.fd, 2000);
            std::this_thread::sleep_for(std::chrono::milliseconds(200));   // let both sends arrive
            char buf[100];
            while (true) {
                ssize_t n = recv(conn.fd, buf, sizeof buf, 0);
                if (n <= 0) break;                                         // 0 = client closed
                pieces.emplace_back(buf, size_t(n));
            }
        });
        {
            lib9::Fd client(socket(AF_INET, SOCK_STREAM, 0));
            if (client.fd >= 0 && connect(client.fd, lib9::sa(&addr), sizeof addr) == 0) {
                send(client.fd, "hello", 5, MSG_NOSIGNAL);
                send(client.fd, "world", 5, MSG_NOSIGNAL);
            }
        }                                                                  // close -> server's recv returns 0
        server.join();
        return pieces;
    }
    }
    """)
    B.code(r"""
    {
        auto pieces = demo9_4::two_sends();
        std::cout << "the server's recv() calls returned " << pieces.size() << " piece(s):";
        std::string all;
        for (const auto& p : pieces) { std::cout << " \"" << p << "\""; all += p; }
        std::cout << "\n";
        CHECK_EQ(all, "helloworld");     // the bytes and their order are guaranteed; the grouping is not
    }
    """)
    B.md(r"""
    To carry **messages** over TCP, the application must mark boundaries itself. The standard
    technique is **length-prefixed framing**: send each message as a 4-byte big-endian length
    followed by the bytes. The receiver accumulates incoming bytes and extracts a message only
    once a length *and* that many bytes are available.

    ```
    stream:  [00 00 00 05][h e l l o][00 00 00 00][00 00 00 03][a b c] ...
               len = 5      message    len = 0       len = 3     message
    recv() may return any slice of this, e.g. "00 00" | "00 05 h e l" | "l o 00 00 00" | ...
    ```
    """)
    B.provided("lib9c", [("1.6", "be")])
    B.exercise("9.4a", "Length-prefixed framing: encoder and decoder",
               r"""
               * `frame_message(msg)`: 4-byte big-endian length, then the bytes.
               * `FrameDecoder::feed(p, n)`: append bytes to `buf`.
               * `FrameDecoder::next()`: if `buf` holds a complete frame, remove it from `buf` and return the message;
                 otherwise return `std::nullopt` and leave `buf` untouched.
               """,
               r"""
               namespace ex9_4a {
               std::vector<uint8_t> frame_message(const std::string& msg) {
                   // TODO (lib9c::write_be32)
                   return {};
               }
               struct FrameDecoder {
                   std::vector<uint8_t> buf;   // received but not yet consumed
                   void feed(const uint8_t* p, size_t n) { }                       // TODO
                   std::optional<std::string> next() { return std::nullopt; }      // TODO
               };
               }
               """,
               r"""
               namespace ex9_4a {
               std::vector<uint8_t> frame_message(const std::string& msg) {
                   std::vector<uint8_t> out(4);
                   lib9c::write_be32(out.data(), uint32_t(msg.size()));
                   out.insert(out.end(), msg.begin(), msg.end());
                   return out;
               }
               struct FrameDecoder {
                   std::vector<uint8_t> buf;   // received but not yet consumed
                   void feed(const uint8_t* p, size_t n) { buf.insert(buf.end(), p, p + n); }
                   std::optional<std::string> next() {
                       if (buf.size() < 4) return std::nullopt;                  // length not complete yet
                       uint32_t len = lib9c::read_be32(buf.data());
                       if (buf.size() - 4 < len) return std::nullopt;            // body not complete yet
                       std::string msg(buf.begin() + 4, buf.begin() + 4 + len);
                       buf.erase(buf.begin(), buf.begin() + 4 + len);            // consume the frame
                       return msg;
                   }
               };
               }
               """,
               r"""
               {
                   CHECK_EQ(ex9_4a::frame_message("hi"), (std::vector<uint8_t>{0x00, 0x00, 0x00, 0x02, 'h', 'i'}));
                   std::vector<std::string> msgs = {"hello", "", "a somewhat longer message", std::string(300, 'z')};
                   std::vector<uint8_t> stream;
                   for (const auto& m : msgs) {
                       auto f = ex9_4a::frame_message(m);
                       stream.insert(stream.end(), f.begin(), f.end());
                   }
                   for (size_t chunk : {size_t(1), size_t(3), size_t(7), size_t(1000)}) {   // every way of slicing
                       ex9_4a::FrameDecoder dec;
                       std::vector<std::string> got;
                       for (size_t off = 0; off < stream.size(); off += chunk) {
                           dec.feed(stream.data() + off, std::min(chunk, stream.size() - off));
                           for (int guard = 0; guard < 10; ++guard) {           // drain complete frames
                               auto m = dec.next();
                               if (!m) break;
                               got.push_back(*m);
                           }
                       }
                       std::cout << "chunk size " << chunk << ": decoded " << got.size() << " messages\n";
                       CHECK(got == msgs);
                   }
               }
               """,
               r"""
               The decoder never assumes a `recv` boundary means anything: it only trusts the length prefix, so every slicing, even
               1 byte at a time, yields the same messages, empty ones included. Writing the check as `buf.size() - 4 < len`
               avoids overflow in `4 + len`. A production decoder also rejects absurd lengths (e.g. > 16 MiB): otherwise a
               malicious peer sends `ff ff ff ff` and makes you wait for, or allocate, 4 GiB.
               """, snippet_key="framing")
    B.provided("lib9d", [("9.4a", "framing")])
    B.exercise("9.4b", "Framing over a real TCP connection",
               r"""
               * `send_all(fd, p, n)`: `send` may accept **fewer** bytes than requested; loop until all are sent. Return `false`
                 on error.
               * `tcp_framed(msgs, recv_calls)`: a server thread accepts one connection and reads with a deliberately tiny
                 buffer, **`recv(fd, buf, 3, 0)`**, feeding a `lib9d::FrameDecoder` and collecting messages until it has
                 `msgs.size()` of them or `recv` returns ≤ 0. Count the `recv` calls in `recv_calls`. The client sends all
                 frames with **one** `send_all`, then closes. Return the messages the server collected. Use the same
                 listen-before-thread, timeout, and join pattern as §9.3.
               """,
               r"""
               namespace ex9_4b {
               bool send_all(int fd, const uint8_t* p, size_t n) {
                   // TODO
                   return false;
               }
               std::vector<std::string> tcp_framed(const std::vector<std::string>& msgs, int& recv_calls) {
                   recv_calls = 0;
                   // TODO
                   return {};
               }
               }
               """,
               r"""
               namespace ex9_4b {
               bool send_all(int fd, const uint8_t* p, size_t n) {
                   while (n > 0) {
                       ssize_t k = send(fd, p, n, MSG_NOSIGNAL);
                       if (k <= 0) return false;            // error (e.g. peer closed)
                       p += k;                              // advance past what was accepted
                       n -= size_t(k);
                   }
                   return true;
               }
               std::vector<std::string> tcp_framed(const std::vector<std::string>& msgs, int& recv_calls) {
                   recv_calls = 0;
                   std::vector<std::string> got;
                   lib9::Fd listener(socket(AF_INET, SOCK_STREAM, 0));
                   sockaddr_in addr = lib9b::make_loopback_addr(0);
                   if (listener.fd < 0 || bind(listener.fd, lib9::sa(&addr), sizeof addr) != 0 ||
                       listen(listener.fd, 1) != 0)
                       return got;
                   lib9b::set_recv_timeout(listener.fd, 2000);
                   addr = lib9b::make_loopback_addr(uint16_t(lib9b::local_port(listener.fd)));

                   std::thread server([&] {
                       lib9::Fd conn(accept(listener.fd, nullptr, nullptr));
                       if (conn.fd < 0) return;
                       lib9b::set_recv_timeout(conn.fd, 2000);
                       lib9d::FrameDecoder dec;
                       uint8_t buf[3];                                   // tiny on purpose
                       while (got.size() < msgs.size()) {
                           ssize_t n = recv(conn.fd, buf, sizeof buf, 0);
                           if (n <= 0) break;
                           ++recv_calls;
                           dec.feed(buf, size_t(n));
                           while (auto m = dec.next()) got.push_back(*m);
                       }
                   });

                   {
                       std::vector<uint8_t> all;                          // every frame, back to back
                       for (const auto& m : msgs) {
                           auto f = lib9d::frame_message(m);
                           all.insert(all.end(), f.begin(), f.end());
                       }
                       lib9::Fd client(socket(AF_INET, SOCK_STREAM, 0));
                       if (client.fd >= 0 && connect(client.fd, lib9::sa(&addr), sizeof addr) == 0)
                           send_all(client.fd, all.data(), all.size());
                   }
                   server.join();
                   return got;
               }
               }
               """,
               r"""
               {
                   std::vector<std::string> msgs = {"first", "", "third message, a bit longer", std::string(5000, 'x')};
                   int calls = 0;
                   auto got = ex9_4b::tcp_framed(msgs, calls);
                   std::cout << "server needed " << calls << " recv() calls for " << got.size() << " messages\n";
                   CHECK(got == msgs);
                   CHECK(calls > int(msgs.size()));                 // many reads per message: boundaries are ours
               }
               """,
               r"""
               The sender wrote everything in one call, the receiver read it 3 bytes at a time, and the messages still came out
               intact, because the framing, not TCP, defines where each message ends. `send_all` matters in practice: on a
               non-blocking socket, or when a signal interrupts the call, `send` can return a short count, and ignoring it
               silently truncates the stream. The `while (auto m = dec.next())` idiom declares `m` inside the condition and
               loops while it holds a value.
               """)

    # ------------------------------------------------------------------ 9.5 ECONNREFUSED
    B.md(r"""
    ## 9.5 Connecting to a closed port: `ECONNREFUSED`

    If a SYN arrives for a port where nothing is listening, the kernel answers with a **RST**
    segment, and the client's `connect` fails immediately with `errno == ECONNREFUSED`.
    To get a port that is certainly closed, bind a socket to port 0, note the port, and close the
    socket without ever calling `listen`.
    """)
    B.exercise("9.5", "Observe ECONNREFUSED",
               r"""
               `connect_to_closed_port(port_used)`: find a closed port as described, store it in `port_used`, then `connect` a
               new TCP socket to it. Return `errno` if `connect` fails, `0` if it (unexpectedly) succeeds, `-1` if the setup fails.
               """,
               r"""
               namespace ex9_5 {
               int connect_to_closed_port(int& port_used) {
                   port_used = -1;
                   // TODO
                   return 0;
               }
               }
               """,
               r"""
               namespace ex9_5 {
               int connect_to_closed_port(int& port_used) {
                   port_used = -1;
                   {
                       lib9::Fd probe(socket(AF_INET, SOCK_STREAM, 0));
                       sockaddr_in a = lib9b::make_loopback_addr(0);
                       if (probe.fd < 0 || bind(probe.fd, lib9::sa(&a), sizeof a) != 0) return -1;
                       port_used = lib9b::local_port(probe.fd);
                   }                                         // closed without listen(): the port is closed
                   lib9::Fd s(socket(AF_INET, SOCK_STREAM, 0));
                   if (s.fd < 0) return -1;
                   sockaddr_in a = lib9b::make_loopback_addr(uint16_t(port_used));
                   if (connect(s.fd, lib9::sa(&a), sizeof a) == 0) return 0;
                   return errno;                             // read errno right after the failing call
               }
               }
               """,
               r"""
               {
                   int port = -1;
                   int err = ex9_5::connect_to_closed_port(port);
                   std::cout << "connect to 127.0.0.1:" << port << " -> errno " << err << " ("
                             << (err > 0 ? std::strerror(err) : "no error") << ")\n";
                   CHECK(port > 0);
                   CHECK_EQ(err, ECONNREFUSED);
               }
               """,
               r"""
               `errno` must be read immediately after the failing call, since any later library call may overwrite it. On loopback the
               RST comes back within microseconds. This is the fastest possible "no" and tells you the **host is reachable but the
               port is closed**.
               """)
    B.question("why", r"""`connect` to a remote server fails after about two minutes with `ETIMEDOUT` rather than instantly with
    `ECONNREFUSED`. What is different about that server's side?""",
               r"""
               `ECONNREFUSED` means a **RST** came back: the host is up but nothing listens on the port. `ETIMEDOUT` means **nothing**
               came back: the SYNs were dropped silently (typically by a firewall configured to drop, or the host is down or
               unreachable), so the client retransmitted the SYN with exponential backoff until it gave up. In debugging,
               "refused" points at the service, while "timeout" points at the network path or a firewall.
               """)
    B.recap(
        ["A socket is a kernel endpoint referenced by an fd; failing calls return −1 and set `errno`.",
         "`sockaddr_in` needs `htons`/`htonl`; bind to port 0 and use `getsockname` to learn the chosen port; clients get ephemeral ports automatically.",
         "UDP: `sendto`/`recvfrom`, one datagram per call, boundaries kept, loss is the application's problem.",
         "TCP: server `socket → bind → listen → accept → recv/send → close`; client `socket → connect → send/recv → close`; `accept` returns a new fd.",
         "TCP has no message boundaries: frame messages (length prefix), loop on `send`/`recv`; RST → `ECONNREFUSED`, silence → `ETIMEDOUT`."],
        ["the exact call sequences of a TCP server and client, and which calls block;",
         "why a timeout on every receiving socket (and `MSG_NOSIGNAL` on sends) is essential;",
         "where the client's port number comes from;",
         "why one `send` is not one `recv`, and how length-prefixed framing fixes it;",
         "what `ECONNREFUSED` versus `ETIMEDOUT` reveals about the other side."])
