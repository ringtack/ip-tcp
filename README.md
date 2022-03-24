# CS 1680: Project IP



## Design

### 1. Link Layer

`protocol/Network.rs` contains the abstraction of our Link Layer. The struct `NetworkInterface` represents each network interface (network cards in reallife). The struct is defined as follows:

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