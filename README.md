# IP/TCP

An RFC-compliant[^1][^2] implementation of IP/TCP over a virtual UDP link layer, built with Rust.[^3]

[^1]: IP: RFC [791](https://datatracker.ietf.org/doc/html/rfc791)
[^2]: TCP: RFCs [793](https://datatracker.ietf.org/doc/html/rfc793) and [1122](https://datatracker.ietf.org/doc/html/rfc1122)
[^3]: Developed for Brown's CSCI1680: Computer Networks.

    - TCP handout: https://cs.brown.edu/courses/csci1680/s22/content/tcp.pdf
    - IP handout: https://cs.brown.edu/courses/csci1680/s22/content/ip.pdf


  * [Usage](#usage)
  * [Benchmarking](#benchmarking)
  * [Performance](#performance)
    + [Local Machine](#local-machine)
    + [Department Machine](#department-machine)
  * [Design](#design)
    + [Node](#node)
    + [TCP](#tcp)
      - [TCPModule](#tcpmodule)
      - [Sockets](#sockets)
      - [Opening a connection](#opening-a-connection)
      - [Sending and receiving data](#sending-and-receiving-data)
      - [Processing segments](#processing-segments)
      - [Handling re-transmission](#handling-re-transmission)
      - [Reviving dead sockets](#reviving-dead-sockets)
    + [IP](#ip)
      - [Link Layer](#link-layer)
      - [RIP Protocol](#rip-protocol)
  * [Packet Capture](#packet-capture)
  * [Bugs and TODOs](#bugs-and-todos)
    + [TCP](#tcp-1)
  * [Appendix](#appendix)


## Usage

To build the nodes, simply run `make` in the base directory:

```bash
$ make
```

To run the nodes, first convert a `.net` configuration file into individual node `.lnx`
configuration files using `tools/net2lnx <.net file>`; this creates a virtual network connected by a
UDP link layer abstraction (see the [Appendix](#Appendix) for more information). Given a `.lnx` file, run the
node with

```bash
$ ./node <.lnx file>
```

## Benchmarking

To benchmark the node's sending capabilities on a lossy network (in this example, we use `ABC.net`), follow the following configuration (make sure to have `in/` and `out/` directories; additionally, `tmux` might help):

- In one terminal, go to the `test/` directory and run the lossy reference IP node with 2% packet loss:
    ```bash
    $ ./ip_node_lossy ./B.lnx
    > lossy 0.02
    ```
- In another terminal, run the node and start the `recvfile` benchmark:
    ```bash
    $ ./node test/C.lnx
    > rf_benchmark out/<file> <port> <num_times>
    ```
- In one last terminal, run the node and start the `sendfile` benchmark (here, `192.168.0.4` is the virtual IP address of the `test/C.lnx` node; make sure to use the same `<port>` and `<num_times>` values):
    ```bash
    $ ./node test/A.lnx
    > sf_benchmark in/<file> 192.168.0.4 <port> <num_times>
    ```

Afterwards, results should appear in the `benchmarks/` directory; files appear as `send_<secs_since_UNIX_EPOCH>.txt`. Happy testing!

To generate your own test files, see the appendix.

> `sf_benchmark`/`rf_benchmark` do not handle failure well; they will survive a failed three-way handshake (although `rf_benchmark` will never finish, since it will wait for too many files), but if a `sendfile` call hits the data or `FIN` re-transmission limit (currently `20`), `sf_benchmark` will forever halt. This isn't a large issue, but it does complicate benchmarking with more iterations/a lossier network.

## Performance

> Note: Previous benchmarks used an RTO lower bound of 10ms, instead of 1ms as recommended on local networks. We've moved the old benchmarks into the `benchmarks/old/` directory, and updated the existing results.

### Local Machine

Performance tests were conducted on a 2018 13" MacBook Pro with a 2.3 GHz Quad-Core Intel Core i5 and 16GB RAM in a Ubuntu 20.04 VM with 2 cores and 2GB RAM.

We observed the following performance for the reference node after 20 sends of 1MB files:
- Over a non-lossy network: **300ms**
- Over a 2% lossy network: **10s**

We ran four performance benchmarks for our node, two for the non-lossy network and two for the 2% lossy network; in each, we sent a 1MB file 50 times.

| File name | Loss % | Reference Node | Our Node | Factor Speedup
| --- | --- | --- | --- | --- |
| send_nonlossy_1651652179_home.txt | 0% | 300ms | **98.9592ms** | **3.0316x** |
| send_nonlossy_1651659042_home.txt | 0% | 300ms | **85.8941ms** | **3.4927x** |
| send_1651695516_home.txt | 2% | 10s | **782.7130ms** | **12.7761x** |
| send_1651695733_home.txt | 2% | 10s | **779.0113ms** | **12.8368x** |

The results are rather promising; although our node varies significantly in time spent, it is able to consistently match and outperform the reference node.

### Department Machine

Similar performance tests were conducted on the CS department machines (specifically, `mlab1e-l`) with even more impressive results.

We observed the following performance for the reference node after 20 sends of 1MB files:
- Over a non-lossy network: **80ms**
- Over a 2% lossy network: **12s**

We again ran four performance benchmarks for our node, two for the non-lossy network and two for the 2% lossy network, with the same configuration.

| File name | Loss % | Reference Node | Our Node | Factor Speedup
| --- | --- | --- | --- | --- |
| send_nonlossy_1651656764_dept.txt | 0% | 80ms | **27.2158ms** | **2.9395x** |
| send_nonlossy_1651657713_dept.txt | 0% | 80ms | **27.0319ms** | **2.9595x** |
| send_1651693707_dept.txt | 2% | 12s | **311.0645ms** | **38.5772x** |
| send_1651638729_home.txt | 2% | 12s | **305.6566ms** | **39.2597x** |

The slowdown on the department machines for the reference node on a 2% lossy network is peculiar, but surprisingly consistent. Our node outperforms the reference node on our local machine, but really shines on the department machines, with sends consistently 1-2s to complete, compared to the reference node's 12s. We hypothesize this may be because the reference node does not make full use of concurrency while our node does, allowing great performance increases on a machine with more cores.


## Design

### Node

A central `Node` structure is the centerpiece of our TCP/IP implementation, providing a command-line interface for all network activities. A node parses a `.lnx` file, which configures its virtual network interfaces (links). Each node provides the following functionality:

```
 ==================== Socket creation/shutdown ====================
 help (h)        : Print this list of commands.
 interfaces (li) : Print information about each interface, one per line.
 routes (lr)     : Print information about the route to each known destination, one per line.
 quit (q)        : Quit this node, closing all open sockets.

 ==================== Socket creation/shutdown ====================
 sockets (ls)    : Print information about each socket (ID, IP, Port, State).
 a [port]        : Spawn a socket, bind it to the given port, and start accepting connections on that port.
 c [ip] [port]   : Attempt to connect to the given ip address, in dot notation, on the given port.
 sd [id] [read|write|both]: Shutdown a socket. "read"/"r" closes only the reading side; "write"/"w"
                            closes only the writing side; "both" closes both. Default is "write".
 cl [id]: v_close on the given socket.

 ==================== Data transmission commands ====================
 s [sid] [data]  : Send a string to a socket. Blocks until v_write() returns.
 r [sid] [n_bytes] [y|n]: Try to read data from a socket. If last argument "y", blocks until n_bytes are
                          read or connection closes. If "n" (default), returns whenever v_read() returns.
 sf [filename] [ip] [port]: Connect to the given IP and port, send the entirety of the specified file, and
                            close the connection.
 rf [filename] [port]: Listen for a connection on the given port. Once established, write everything you can
                       read from the socket to the given file. Once the other side closes the connection, close
                       the connection as well.


 ==================== IP/network commands ====================
 send [ip] [protocol] [payload] : sends payload with the specified protocol to the virtual IP address.
 up [integer]   : Bring an interface "up" (it must be an existing interface, probably one you brought down).
 down [integer] : Bring an interface "down".

 ==================== Logging commands ====================
 log [id]: print SendControlBuffer and RecvControlBuffer information about socket with the specified id.
 sf_benchmark [filename] [ip] [port] [n]: Send a file to the destination socket n times, then display benchmarks.
 rf_benchmark [filename] [port] [n]: Receive a file on the provided port n times, then display benchmarks.
```

### TCP

Most of the TCP RFC is supported, including:
- IPv4 header checksum generation/validation
- Configurable MSS/window sizes
- Three-way handshake and graceful shutdown, including simultaneous `SYN`s/`FIN`s
- `SYN`/`FIN` re-transmission and timeouts
- Adherence to the TCP state diagram
- Zero-window probing with exponential backoff
- Data re-transmission with exponential backoff
- Send/receive sequence space maintenance (including circular sequence numbers)
- Out-of-order segments [TODO]

Currently, urgent pointers, RST packets, TCP options, congestion control, and security/precedence fields are not supported. Nagle's algorithm, delayed `ACK`s, `SYN`/`FIN` segments with data, clock-generated `ISN`s, SWS avoidance, selective `ACK`s, and Jacobson's + Korn's SRTT algorithm are in progress, but not completely supported at the moment. See the TODOs for more.

#### TCPModule

The `TCPModule` struct is the primary TCP interface responsible for all socket operations:

```rust
pub struct TCPModule {
    ip_module: InternetModule,                                            // interface to IP layer
    sockets: SocketTable,                                                 // list of all sockets
    listen_queue: Arc<DashMap<SocketEntry, SynchronizedQueue<SocketID>>>, // sockets from listeners
    pending_socks: Arc<DashSet<SocketEntry>>,                             // sockets that potentially need re-transmission
    send_tx: SyncSender<IPPacket>,                                        // channel for sockets to forward IP packets
    accept_tx: Sender<IPPacket>,                                          // channel for listener sockets to accept connections
    segment_tx: Sender<IPPacket>,                                         // channel to handle incoming segments
}
```

On creation, the `TCPModule` struct additionally spawns 5 handler threads (`send_loop`, `accept_loop`, `segment_loop`, `retransmission_loop`, and `dead_socket_loop`). We describe each field and handler in the following sections. In addition, a TCP protocol handler is provided to the network layer (allowing the IP module to forward TCP packets to the TCP module), which sends packets either to the accepting connections or processing segments handler, depending on the destination socket.

The `TCPModule` struct supports most of the functionality expected from a socket API:
```rust
    /**
     * Creates a new socket and binds the socket to an address/port. If addr is nil/0, bind to any
     * available interface.
     *
     * After binding, moves socket into LISTEN state (passive OPEN in the RFC).
     *
     * Returns:
     * - socket number on success or negative number on failure
     */
    pub fn v_listen(&self, addr: Ipv4Addr, port: u16) -> TCPResult<SocketID>;
    
    /**
     * Accept a requested connection from the listening socket's connection queue.
     *
     * Returns:
     * - new socket handle on success or error on failure
     */
    pub fn v_accept(&self, id: SocketID) -> Result<SocketID>;
    
    /**
     * Creates a new socket and connects to an address (active OPEN in the RFC).
     *
     * Returns:
     * -  the socket number on success, or Err on failure
     */
    pub fn v_connect(&self, addr: Ipv4Addr, port: u16) -> Result<SocketID>;
    
    /**
     * Read on an open socket (RECEIVE in the RFC). REQUIRED to block when there is no available
     * data. All reads should return at least one data byte unless failure or EOF occurs.
     *
     * Returns:
     * - (num bytes read) or (negative number on failure) or (0 on EOF and shutdown_read) or (0 if
     *    nbyte = 0)
     */
    pub fn v_read(&self, id: SocketID, buf: &mut [u8], n_bytes: usize) -> TCPResult<usize>;

    /**
     * Write on an open socket (SEND in the RFC). Write is REQUIRED to block until all bytes are in
     * the send buffer.
     *
     * Returns:
     * - (num bytes written) or (negative number on failure)
     */
    pub fn v_write(&self, id: SocketID, buf: &[u8]) -> TCPResult<usize>;

    /**
     * Shutdown an connection.
     *
     * - if `how` is WriteClose, close the writing part (CLOSE from RFC, i.e. send FIN)
     * - if `how` is ReadClose, close the reading part (no equivalent; all v_reads should return
     *   0).
     * - if `how` is BothClose, close both ends.
     *
     * Returns:
     * - nothing on success, error on failure.
     */
    pub fn v_shutdown(&self, id: SocketID, how: ShutdownType) -> TCPResult<()>;
    
    /**
     * Close the socket, making the underlying connection inaccessible to the TCP API functions.
     * The connection will finish retransmitting any data not yet ACK'd.
     *
     * Returns:
     * - Nothing on success, error on failure.
     */
    pub fn v_close(&self, id: SocketID) -> TCPResult<()>;
```

#### Sockets

Each socket (Transmission Control Buffer/TCB in the RFC) is stored in a TCP module-wide `SocketTable`, accessible both by a socket ID (assigned from `0` upwards) and a `SocketEntry` (a four-tuple of `(src_addr, src_port, dst_addr, dst_port)`), and has the following fields:

```rust
pub struct Socket {
    src_sock: SocketAddrV4,                     // source <address>:<port>
    dst_sock: SocketAddrV4,                     // destination <address>:<port>
    tcp_state: Arc<Mutex<TCPState>>,            // current state of the socket

    time_wait: Arc<Mutex<Option<Instant>>>,     // timer for TimeWait (and other closing states)
    zero_probe: Arc<Mutex<Option<Instant>>>,    // zero-probing re-transmission timer
    zp_counter: Arc<AtomicU32>,                 // counter to determine interval between zero-probes
    zp_timeout: Arc<AtomicU32>,                 // counter to determine timeout for zero-probing
    prtt: Arc<Mutex<Duration>>,                 // predicted RTT
    rtx_q: Arc<Mutex<VecDeque<SegmentEntry>>>,  // segment retransmission queue

    snd: Arc<Mutex<SendControlBuffer>>,         // SND circular buffer
    rcv: Arc<Mutex<RecvControlBuffer>>,         // RCV circular buffer
    send_tx: SyncSender<IPPacket>,              // interface to IP module for packet forwarding
    nagles: Arc<AtomicBool>,                    // flag for Nagle's algorithm
}
```

A socket's current state in the TCP state diagram is tracked via `tcp_state`. Each socket contains two circular buffers, `snd` and `rcv`, responsible for maintaining send/receive sequence space values (e.g. `SND.{UNA, NXT, WND}` and `RCV.{NXT, WND}`). `nagles` may be used to enable/disable Nagle's algorithm (... which currently doesn't work anyways 😅).

> Although each socket possesses information about timeouts, the main TCP module's `pending_socks` is currently missing (more on this later); this makes handling re-transmission particularly ugly within socket methods, which unfortunately forces re-transmission handling in other interfaces. Ideally, a socket should be responsible for putting itself on/taking itself of the `pending_socks` set.

> Additionally, `snd`/`rcv` are guarded by mutexes, but each is locked within other handlers that may call socket-specific methods (e.g. `send_buffer`, `recv_buffer`, etc.); this results in an unfortunate API/separation of concerns, wherein calling functions must first do some processing with `snd`/`rcv` before calling socket methods. We're not quite sure how to remedy this yet, given Rust's safe synchronization model.

Each socket additionally has a few timers/counters:
- `time_wait`: records the time since entering a closing state (`FIN-WAIT-1`, `FIN-WAIT-2`, `CLOSING`, `LAST-ACK`, and `TIME-WAIT`).
- `zero_probe`: records the time since the last zero-probe.
- `zp_counter`/`zp_timeout`: records the number of times the node has zero-probed with a response (`counter`) or without (`timeout`).
- `prtt`: computes the predicted RTT, adhering to RFC 793's naive computation (we attempted Jacobson's + Korn's algorithm, but ran out of time).

Sockets communicate with other sockets through the `send_{tx, rx}` channel; segments are sent to the `send_loop` handler, which is responsible for interfacing with the `ip_module` and forwarding packets.

> In hindsight, more feedback from the `send_loop` would help in providing user responses to failed `send`/`shutdown`/`close` attempts; right now, the `send_loop` is a very thin loop that continually processes segments from the channel, which is unfortunately a bottleneck for packet transmission. Perhaps the channel may be done away with altogether, and just directly sent through the IP module.

#### Opening a connection

A listener socket for incoming connections may be established by providing a port number to `v_listen`; the port number is first validated (it must be `> 1024`, and not currently in use), then `v_listen` creates a socket on `0.0.0.0:<port>` in the `LISTEN` state (`PASSIVE OPEN` in the RFC). A synchronized queue is added for the socket in the TCP module's `listen_queue` map; when incoming connections arrive, the listener socket spawns a new TCB, and if the three-way handshake is successfully established, the newly accepted socket is added to the listener socket's `listen_queue`. Subsequent `v_accept` calls on the listener socket's ID take from this queue to return new connections.

A connection is made via the `v_connect` call by providing the destination IP address/port combination (`ACTIVE OPEN` in the RFC); a `SYN` segment is sent, and the socket is put on the `pending_socks` set. When a `SYN+ACK` segment is received, the socket transitions into the `ESTABLISHED` state and removed from the `pending_socks` set.

Segments to `ACTIVE OPEN` sockets are forwarded from the TCP protocol handler through the `accept_{tx, rx}` channel, and processed by the accepting connections handler. If the appropriate values are `ACK`ed from a valid source to the valid destination, the handler performs the above transition from `SYN-SENT` to `ESTABLISHED`.

> In hindsight, there is no real reason for the separation between accepting connections and handling segments (described later); we originally thought it'd be a nice abstraction, but only yielded an arbitrary division of responsibilities. We kept it out of time constraints, but would like to combine them into a more modular handler later.

#### Sending and receiving data

Data is sent/received via the `v_read`/`v_write` calls (`SEND` and `RECEIVE` in the RFC, respectively); after supplying a buffer, the TCP module will send/receive data from/into the buffer to the other end of the connection. `v_read` blocks until at least `1` byte is received in the `RCV` buffer; `v_write` blocks until *all* bytes are *written into* the `SND` buffer (but not necessarily fully sent out and `ACK`ed!).

> When sending out, all bytes from `SND.NXT` to `SND.UNA + SND.WND` are sent; if a large buffer is written, this may spam the connection with multiple data segments, perhaps before the receiving end may respond to all of them. If not enough time elapses between `ACK`s, the receiving node may `ACK` too little a sequence number, causing unnecessary data re-transmissions, and slowing throughput through the underlying link. This problem is especially exacerbated when an early segment is dropped from the network.

#### Processing segments

The core of our TCP implementation is the `segment_loop`, responsible for handling all incoming segments. The sequence number is first checked for acceptability; if outside of the window, the segment is dropped. Then, depending on the state and segment, the handler responds according to the RFC. As a non-exhaustive list:
- if in `SYN-RCVD` and the `SYN` is `ACK`ed, transition into `ESTABLISHED` state.
- if `SND.UNA < SEG.ACK <= SND.NXT`, update `SND.UNA` (and related values); if `SND.UNA == SEG.ACK` and `SND.WND != SEG.WND`, update the window (a bug in RFC 793, later corrected in the [errata](https://www.rfc-editor.org/errata/eid4785)).
- If `SEG.WND == 0` or `SND.WND == 0 && SEG.WND > 0`, start/stop zero-probing.
- if the `FIN` bit is set, transition into a closing state depending on the current state.
- If the `SND` buffer is non-empty, instead of just sending an `ACK` back, send all bytes from `SND.NXT` to `SND.UNA + SND.WND`.

View the code in `tcp_utils.rs` for the entire handling process (although it adheres to the RFC rather strictly).

> Because all processing of segments is done here, and each socket's `snd`/`rcv` must be locked before processing, the receiving socket is essentially blocked for the duration of an iteration of the `segment_loop`; this may be problematic for simultaneous `send`/`recv` calls, as only one thread may act on the socket for both sending and receiving bytes. Moreover, each of the socket's fields are essentially wrapped in `Arc<Mutex<T>>`s—which are accessed across multiple threads—causing increased lock contention that can considerably slow down segment handling.

> Additionally, because async is not currently supported and re-transmission handling is incredibly unergonomic, delayed `ACK`s are incredibly complex and thus not currently supported. This can slow down processing, and result in a flood of `ACK` segments when out-of-order segments are received.

> Finally, if a large amount of segments are being sent at once, chances are `v_write` is also sending segments; when we then check if the `SND` buffer is non-empty and send bytes from `SND.NXT` onwards, duplicate segments may be sent, flooding the network.

#### Handling re-transmission

The majority of the re-transmission logic (for `SYN`, `FIN`, and data segments) is done within the `retransmission_loop` handler. Whenever a socket has any need for re-transmission (i.e. sending a `SYN`/`FIN`/data segment, or zero-probing), it should be added to the TCP module's `pending_socks` set to indicate that re-transmission is necessary; and whenever the pending segment is fully `ACK`ed, the socket should be removed. Every `5000μs`, the `retransmission_loop` iterates through the entire `pending_socks` set, and handles each pending socket.

> We'd really prefer not to busy-loop through the pending sockets list, as each of the data structures accessed (the `pending_socks` queue, the `sockets` table, and many of the socket's fields, e.g. its timers) are protected behind synchronization primitives. This greatly increases lock contention, and wastes CPU power on often-unnecessary checks. We limit the effect of this by sleeping for `5000μs` every iteration; since the lower bound on re-transmission is `10ms`, this should allow the loop to process re-transmissions in a timely fashion while not consuming too much CPU power. Still, we'd prefer to transition into a cleaner model (i.e. async), as the current structure is highly inflexible, rather inefficient, and unconducive to further changes like delayed ACKs, congestion control, effective zero-probing, and RTO calculations, among other stuff.

Each socket maintains a `rtx_q` of pending segments, that must be ordered starting from the lowest `SEQ` number. All pending segments are checked against the socket's `SND.UNA`; if the end of the segment (`SEG.SEQ + SEG.LEN`) is below the `SND.UNA` (i.e. it was `ACK`ed before), it is removed from the re-transmission queue. If a socket's `rtx_q` is empty, it must have been fully acknowledged, and is thus removed from the `pending_socks` set. Otherwise, the pending segment is checked against its exponentially backoff-ed timeout (computed via the segment's re-transmission counter and the socket's own timers), and either returned to the pending re-transmission queue or sent again with an increased re-transmission counter (if timeout).
- Because `SYN`/`FIN` segments are also appended to `rtx_q`, handling of these segments is almost identical to data segments, so very little special casing is necessary; similarly with zero-probing. The primary difference lies in calculating timeouts (it gets slightly wonky with zero-probing) and re-transmission limits (currently `3` for `SYN` segments and `20` for data/`FIN`/zero-probing segments).

> In general, our re-transmission code is not particularly modular, and breaks separation of concerns; this led to multiple deadlocks/panics while implementing. It's pretty ugly, but it works for now :,)

#### Reviving dead sockets

When sending a large file, there is a brief window in which the sending thread could block indefinitely: if the sending socket has fully sent out its send buffer (i.e. `SND.NXT = SND.UNA + SND.WND`) and the receiving window hits `0`, the socket *will not* begin zero-probing (as there's nothing with which to probe). The receiving socket will never then update the sending socket about its increased window size, and the sending socket will remain forever stuck. We went with a rather naive way of fixing the code: in `dead_socket_loop`, a thread loops over every socket every second, and if the socket:
- is in a writable state (i.e. `ESTABLISHED` or `CLOSE-WAIT`),
- has a non-empty `SND` buffer,
- has an empty `SND` window (i.e. `SND.WND == 0`),
- and is not currently zero-probing,

the thread initiates zero-probing for the socket. This is rather inefficient, but every second is really not that bad in terms of CPU usage (and with our current performance, shouldn't negatively impact sending speeds for super large files; although maybe that just says something about our performance...)

Another, perhaps better, fix could be to include the `pending_socks` set in either the socket's `send_buffer()` method, or as a field (which could make the code slightly more ergonomic elsewhere anyways); this would require greater architectural adjustments, but could feasibly work.

### IP

> TODO: this section is currently under development.

#### Link Layer

`network.rs` contains the abstraction of our UDP link layer. The `NetworkInterface` struct
represents each network interface (network cards in real life):
```rust
pub struct NetworkInterface {
    pub id: u8,                     // the unique ID of this network interface.
    pub src_addr: net::Ipv4Addr,    // the source IP address of this interface.
    pub dst_addr: net::Ipv4Addr,    // the destination IP address of this interface.
    pub link_if: LinkInterface,     // the link interface of the destination.
}
```

Each `Node` contains an vector of `NetworkInterface`s, akin to a server having multiple network cards.

#### RIP Protocol

For routing, our network uses the RIP protocol. On node start, 5 handlers (threads) are created for the RIP protocal:

- Checking timeouts
- Sending triggered updates
- Sending periodic updates
- Listening for messages and sending them to a channel
- Receiving messages from channel and processing them


## Packet Capture

In the `captures/` directory, some Wireshark captures of our nodes in action exist. To use Wireshark with our UDP link layer abstraction, view the `README.md` in the `rip_dissector/` directory. We've annotated a view captures here:

#### `1MB_lossy_capture.pcapng`

This is a packet capture of two nodes running on `ABC.net` running `A.lnx` and `C.lnx` respectively, with the reference `ip_node_lossy` running `B.lnx` with 2% packet loss. To view output from only the sending node, enter the display filter

```
not cs168rip and udp.srcport == 5000
```

Similarly, to view output from only the receiving node, enter the display filter

```
not cs168rip and udp.srcport == 5002
```

- Frame #39 is the initial `SYN` segment; it is `SYN+ACK`ed by the receiving node in Frame #41, and finally `ACK`ed by the sending node in Frame #43.
- The sending node begins transmitting data in segments of size `MSS=1024` (same as the reference node). Frame #43 shows a sent segment, which is later acknowledged by the receiving node in Frame #131.
    * Inspecting the lossy node (`udp.srcport == 5001`), the packet with `SEG.SEQ=1025` is dropped, meaning only one segment actually made it into the other node's `RCV` buffer (at least without out-of-order segments), which required the sending node to re-transmit everything from `SEG.SEQ=1025` to `SEG.SEQ=65536` (Frames #302 to #391). The segments are then successfully `ACK`ed by the receiving node in Frames #392 to #417, then again from #514 to #610.
- Frame #12111 marks the connection teardown, initiated by the sending node via a `FIN` segment; the receiving node `ACK`s the `FIN` in Frame #12113, then sends its own `FIN` in Frame #12115. It is finally `ACK`ed by the sending node in Frame #12117.

#### `1MB_lossy_capture_2.pcapng`

This is a packet capture using the same set-up as above.

- Frame #5 is the initial `SYN` segment; it is `SYN+ACK`ed by the receiving node in Frame #7, and finally `ACK`ed by the sending node in Frame #9.
- The sending node then begins transmitting data in segments of size `MSS=536B` (as specified by the RFC). Frame #11 shows a sent segment (later forwarded by the middle node in Frame #27), which is later acknowledged by the receiving node in Frame #263.
- Starting from Frame #379 until roughly Frame #500, segments were likely lost by the middle node earlier, and thus re-transmitted by the sending node. The receiving node `ACK`s the re-transmitted segments from Frame #609 to roughly Frame #640.
- Frame #14645 marks the connection teardown, initiated by the sending node via a `FIN` segment; the receiving node `ACK`s the `FIN` in Frame #14647, then sends its own `FIN` in Frame #14648. It is finally `ACK`ed by the sending node in Frame #14656.

## Bugs and TODOs

### TCP

Certain bugs exist within the implementation; although most likely won't crash our node, they
will halt some functionality:

- [ ] Re-transmission is not *fully* correct; our current re-transmission limit is set at `20`, but a socket may timeout itself even if it might not hit the limit; whenever a segment is re-transmitted, a counter is increased by one, and if the limit is hit, the socket shuts down. This doesn't take into account the status of the receiving node; even if the node correct `ACK`s a segment, if its value is lower than the re-transmittiing segment's `SEQ`, then the counter is not reset. This causes sockets to sometimes shut down even when connected and sending data.
- [ ] Closing a socket via `v_close()`/`quit` (on the node) doesn't wait until re-transmission is
      completely done, and the other end of the socket cannot connect to the socket following a
      `v_close()` operation (even though it should be able to, according to the reference node). Such
      a change---rendering a socket both completely inaccessible to the socket API, yet still capable
      of receiving/re-transmitting---would take large architectural rehauls, something that I'd like
      not to do right now (given the immense technical debt we've since accrued).
- [ ] Special-casing around the send sequence number space is too lax; if someone sent a file over
      `2^32B`, it would likely break the send/receive buffers' circularity. Fixing it shouldn't be
      difficult, just annoying. Perhaps I'll tackle this in the far future.
- [ ] Corner cases within the state diagram are not well tested; I would not be surprised if some bug
      emerged in the transitions.


Additionally, there are multiple TODOs that would (hopefully) improve performance of our node:

- [ ] Accepting out-of-order segments: we should ideally finish this before interactive grading...
      The infrastructure is mostly there, we just need to add a priority queue to store out-of-order
      segments; as more segments arrive, if the priority queue already has later segments, we could
      just take out of there. I believe the only change needed should be within `recv_buffer` (as we
      clear the receive buffer, if later segments exist, flush them as well) and the writing data
      section in `make_segment_loop`.
- [ ] A working implementation of Nagle's Algorithm/Delayed ACK: the code is already there for
      Nagle's Algorithm, but it fails to send data when the amount of data is less than `MSS` (maybe
      this is intended?), causing small sends to become lost in the void (without a large send later).
      The current structure makes implementing delayed ACK quite painful; the below change would
      help...
- [ ] `async` Rust/transitioning to tokio: the only real method of handling re-transmission at the
      moment is essentially busy-looping through sockets that might need re-transmission, which is
      both unconducive for optimizations like delayed ACK, and overall inefficient. It may be too
      convoluted, but `async` could hypothetically clean up the code structure immensely.
- [ ] Structural cleanup: in general, the code would benefit from structural re-writes. Currently, essentially all of the segment handling is done in one handler (`segment_handler`), leading to a monolithic handler function prone to many bugs (this happens elsewhere too...). Async will help, but cleanup in general would be helpful.
- [ ] Congestion control: there is too much technical debt to tackle this at the moment, but it
      would sure be cool...

# Appendix

#### `.net`/`.lnx` Configuration Files

TODO

#### Generating/verifying test files

To create your own test files, use the following command:

```bash
dd if=/dev/urandom of=<out_file> bs=<size> count=1
```

This copies `<size>` bytes from `/dev/urandom` into `<out_file>` (we've generated one such file, `in/long`, with `size=1M`).

To verify that input and output files are identical, you can either use

```bash
diff <in_file> <out_file>
```

or

```bash
sha1sum <in_file> <out_file>
```
