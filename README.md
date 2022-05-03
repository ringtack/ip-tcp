# IP/TCP[^1]

An RFC-compliant implementation of IP/TCP over a virtual UDP link layer, built with Rust.

[^1] Developed for Brown's CSCI1680: Computer Networks. See the TCP handout [here](https://cs.brown.edu/courses/csci1680/s22/content/tcp.pdf), and the IP handout [here](https://cs.brown.edu/courses/csci1680/s22/content/ip.pdf).

## Usage

To build the nodes, simply run

```bash
make
```

in the base directory (bless Cargo).

To run the nodes, first convert a `.net` configuration file into individual node `.lnx`
configuration files using `tools/net2lnx <.net file>`; this creates a virtual network connected by a
UDP link layer abstraction (see the Appendix for more information). Given a `.lnx` file, run the
node with

```bash
./node <.lnx file>
```

## Design

### TCP

#### `TCPModule`

The `TCPModule` struct is the primary TCP interface responsible for all socket operations:

```rust
pub struct TCPModule {
    ip_module: InternetModule, // interface to IP layer
    pub sockets: SocketTable, // list of all sockets
    listen_queue: Arc<DashMap<SocketEntry, SynchronizedQueue<SocketID>>>, // sockets from listeners
    pub pending_socks: Arc<DashSet<SocketEntry>>, // sockets that potentially need re-transmission
    send_tx: SyncSender<IPPacket>, // channel for sockets to forward IP packets
    pub accept_tx: Sender<IPPacket>, // channel for listener sockets to accept connections
    pub segment_tx: Sender<IPPacket>, // channel to handle incoming segments
}
```

## Bugs/TODOs

### TCP

Certain bugs exist within the implementation; although most likely won't crash our node, they
will halt some functionality:

- [x] When sending a large file, there is a brief window in which the sending thread could block
      indefinitely: if the sending socket has fully sent out its send buffer (i.e. `SND.NXT = SND.UNA + SND.WND`)
      and the receiving window hits `0`, the socket _will not_ begin zero-probing (as there's nothing
      with which to probe). The receiving socket will never then update the sending socket about its
      increased window size, and the sending socket will remain forever stuck.

      The fix to this shouldn't be overly difficult, although may require some re-structuring within
      code. One naive option may be just to loop over every socket every so often, and if `SND.WND == 0`
      yet the send buffer is non-empty, send a zero-probe; this would be rather inefficient, but should
      be able to restart dead sockets. Another option could be to include the `pending_socks` set in
      either the socket's `send_buffer()` method, or as a field (which could make the code slightly more
      ergonomic elsewhere anyways); this would require greater architectural adjustments, but could
      feasibly work.

          - Fixed! I went with the first naive fix. Some day, I'll take a look at this again...

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
- [ ] Congestion control: there is too much technical debt to tackle this at the moment, but it
      would sure be cool...

## Design

### 1. Link Layer

`protocol/Network.rs` contains the abstraction of our Link Layer. The struct `NetworkInterface`
represents each network interface (network cards in reallife). The struct is defined as follows:

```rust
/**
 * Struct representing a single network interface.
 *
 * Fields:
 * - id: the unique ID of this IF.
 * - src_addr: the IP address of the source IF.
 * - dst_addr: the IP address of the dest IF.
 * - link_if: the link interface of the destination.
 */
pub struct NetworkInterface {
    pub id: u8,
    pub src_addr: net::Ipv4Addr,
    pub dst_addr: net::Ipv4Addr,
    pub link_if: LinkInterface,
}
```

Each `Node` contians an vector of `NetworkInterface`, just like a server could be connected to multiple network cards.

### 2. RIP Protocol

On node start, 5 handlers (threads) are created for the RIP protocal:

- Checking timeouts
- Sending triggered updates
- Sending periodic updates
- Listening for messages and sending them to a channel
- Receiving messages from channel and processing them

## How-to

### 1. Build

```bash
make
```

### 2. Run

```bash
./node <path to lnx file>
```

# Appendix

## `.net`/`.lnx` Configuration Files

TODO
