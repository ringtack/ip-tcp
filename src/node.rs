use crate::protocol::link::READ_TIMEOUT;
use crate::protocol::network::{
    ip_packet::*, network_interfaces::*, rip::*, routing_table::*, test::*, InternetModule,
};
use crate::protocol::tcp::{tcp_socket::ShutdownType, tcp_utils::make_tcp_handler, *};

use dashmap::DashMap;
use std::{
    fs::File,
    io::{prelude::*, BufRead, BufReader, Error, ErrorKind, Lines, Result},
    net::{Ipv4Addr, SocketAddrV4, UdpSocket},
    path::Path,
    process,
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc::{channel, Sender},
        Arc,
    },
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

// directory to store send benchmark results
pub const SEND_BENCHMARKS_DIR: &str = "benchmarks";

/**
 * Struct representing the network layer interface.
 */
pub struct Node {
    ip_module: InternetModule,
    tcp_module: TCPModule,
    trigger: Sender<Ipv4Addr>,
    ip_threads: Vec<thread::JoinHandle<()>>,
    // tcp_threads: Vec<thread::JoinHandle<()>>,
    stopped: Arc<AtomicBool>,
}

impl Node {
    pub fn new(linksfile: String) -> Result<Node> {
        // Attempt to parse the linksfile
        let lines = read_lines(&linksfile)?;

        // if successful, create initial interface and routing table
        let mut ifs = NetworkInterfaces::new();
        let rt = RoutingTable::new();
        // store src socket; shared across all interfaces
        let mut src_sock = None;

        // iterate through every line
        for (index, line) in lines.enumerate() {
            let line = line?;
            let line: Vec<&str> = line.split_whitespace().collect();
            // regardless of source or dest, gets addr:port
            let sock_addr =
                SocketAddrV4::new(str_2_ipv4(line[0])?, line[1].parse::<u16>().unwrap());

            // if first line, is source "L2 address"
            if index == 0 {
                // Create socket on which node will listen
                println!("[Node::new] Listening on {}...", sock_addr);

                let sock = UdpSocket::bind(sock_addr)?;
                sock.set_read_timeout(Some(Duration::from_millis(READ_TIMEOUT)))?;
                src_sock = Some(sock);
                continue;
            }

            // otherwise, make network interface:
            //      <Dest L2 Address> <Dest L2 Port> <Src IF> <Dest IF>
            let src_addr = str_2_ipv4(line[2])?;
            let dest_addr = str_2_ipv4(line[3])?;

            if let Some(sock) = &src_sock {
                ifs.insert(NetworkInterface::new(
                    (index - 1) as u8,
                    src_addr,
                    dest_addr,
                    sock,
                    sock_addr,
                )?);
            }

            // insert into routing table
            rt.insert(Route {
                dst_addr: src_addr,
                gateway: src_addr,
                next_hop: src_addr,
                cost: 0,
                mask: INIT_MASK,
                timer: Instant::now(),
            })?;
        }
        /* ====================================================================
         * Protocol Handlers Setup
         * ====================================================================
         */
        // Create structs for InternetModule construction
        let ifs = Arc::new(ifs);
        let rt = Arc::new(rt);
        let stopped = Arc::new(AtomicBool::new(false));
        // create sender and receiver for trigger updates
        let (tx, rx) = channel::<Ipv4Addr>();

        // Create structs for TCPModule construction [TODO: need this scuffed way so I don't need
        // to use a RwLock/Mutex for the handlers map... need a better way of doing this]
        // let sockets = SocketTable::new();
        // let listen_queue = Arc::new(DashMap::new());
        // let pending_socks = Arc::new(DashSet::new());
        // let (send_tx, send_rx) = sync_channel(CHAN_BOUND);
        // let (accept_tx, accept_rx) = channel();
        // let (segment_tx, segment_rx) = channel();

        let handlers = Arc::new(DashMap::new());
        let ip_module = InternetModule::new(rt.clone(), ifs.clone(), handlers.clone());
        // create Node!
        let mut node = Node {
            ip_module: ip_module.clone(),
            tcp_module: TCPModule::new(
                ip_module,
                // sockets,
                // listen_queue,
                // pending_socks,
                // send_tx,
                // send_rx,
                // accept_tx,
                // accept_rx,
                // segment_tx,
                // segment_rx,
            ),
            trigger: tx.clone(),
            ip_threads: Vec::new(),
            // tcp_threads: Vec::new(),
            stopped: stopped.clone(),
        };

        /* ====================================================================
         * Protocol Handlers Setup
         * ====================================================================
         */
        handlers.insert(TEST_PROTOCOL, make_test_handler(ifs.clone()));
        handlers.insert(
            RIP_PROTOCOL,
            make_rip_handler(ifs.clone(), rt.clone(), tx.clone()),
        );
        handlers.insert(
            TCP_PROTOCOL,
            make_tcp_handler(
                node.tcp_module.sockets.clone(),
                node.tcp_module.accept_tx.clone(),
                node.tcp_module.segment_tx.clone(),
            ),
        );
        /* ====================================================================
         * Thread Handlers Setup
         * ====================================================================
         */
        // set up cleanup thread in RoutingTable
        node.ip_threads
            .push(RoutingTable::make_rt_cleanup(rt, tx, stopped.clone()));

        // set up trigger response thread
        node.ip_threads
            .push(node.ip_module.make_trigger_response(rx, stopped.clone()));

        // set up periodic RIP update thread
        node.ip_threads
            .push(node.ip_module.make_periodic_updates(stopped.clone()));

        // send initial RIP Request to network interfaces (i.e. neighbors)
        for dest_if in ifs.iter() {
            send_rip_message(dest_if, RIPMessage::new(RIP_REQUEST, 0, vec![]))?;
        }

        // Set up packet listener thread
        node.ip_threads
            .push(node.ip_module.clone().make_ip_listener(stopped));

        // print out startup interfaces
        println!("{}", node.ip_module.fmt_startup_interfaces());

        Ok(node)
    }

    /**
     * Gracefully exit the node.
     */
    pub fn quit(&mut self) {
        // close all sockets.
        self.tcp_module.close_all();

        // notify all threads that we're done by updating stopped flag
        self.stopped.store(true, Ordering::Relaxed);

        // join all threads
        while let Some(cur_thr) = self.ip_threads.pop() {
            cur_thr.join().expect("Thread failed to join.");
        }

        // Send RIP message indicating death to local interfaces
        self.ip_module.send_exit_msg();
        // ... aaaand we're done! :D
    }

    /**
     * Handle command input.
     */
    pub fn handle_command(&mut self, args: &[&str]) {
        match args[0] {
            "help" | "h" => println!("{}", HELP_MSG),
            "interfaces" | "li" => println!("{}", self.ip_module.fmt_interfaces()),
            "routes" | "lr" => println!("{}", self.ip_module.fmt_routes()),
            "sockets" | "ls" => println!("{}", self.tcp_module.fmt_sockets()),
            "a" => {
                if args.len() != 2 {
                    eprintln!("Usage: \"a <port>\"");
                    return;
                }
                match args[1].parse::<u16>() {
                    Ok(port) => {
                        let l_id = match self.tcp_module.v_listen(0.into(), port) {
                            Ok(l_id) => l_id,
                            Err(e) => {
                                eprintln!("{}", e);
                                return;
                            }
                        };
                        let tcp_module = self.tcp_module.clone();
                        thread::spawn(move || loop {
                            // Continually accept and print information about established
                            // connections
                            let c_id = match tcp_module.v_accept(l_id) {
                                Ok(c_id) => c_id,
                                Err(e) => {
                                    eprintln!("{}", e);
                                    break;
                                }
                            };
                            println!("v_accept({}) returned {}", l_id, c_id);
                        });
                    }
                    Err(e) => eprintln!("{}", e),
                }
            }
            "c" => {
                if args.len() != 3 {
                    eprintln!("Usage: \"c <ip> <port>\"");
                    return;
                }
                match args[2].parse::<u16>() {
                    Ok(port) => {
                        let addr = match str_2_ipv4(args[1]) {
                            Ok(addr) => addr,
                            Err(e) => {
                                eprintln!("Error parsing address: {}", e);
                                return;
                            }
                        };
                        match self.tcp_module.v_connect(addr, port) {
                            Ok(c_id) => {
                                println!("Opened new socket with ID {}.", c_id);
                            }
                            Err(e) => eprintln!("{}", e),
                        };
                    }
                    Err(e) => eprintln!("{}", e),
                }
            }
            "s" => {
                if args.len() < 3 {
                    eprintln!("Usage: \"s <socket id> <data...>\"");
                    return;
                }
                let data = args[2..].to_vec().join(" ");
                match args[1].parse::<u8>() {
                    Ok(sid) => match self.tcp_module.v_write(sid, data.as_bytes()) {
                        Ok(n) => {
                            let (src_sock, dst_sock) = self.tcp_module.get_sock_entry(sid).unwrap();
                            println!(
                                "[{}] Put {} bytes on send buffer to {}.",
                                src_sock, n, dst_sock
                            );
                        }
                        Err(e) => eprintln!("{}", e),
                    },
                    Err(e) => eprintln!("{}", e),
                }
            }
            "r" => {
                if args.len() < 3 || args.len() > 4 {
                    eprintln!("Usage: \"r <socket id> <n_bytes> <y|n>\"");
                    return;
                }
                let block = if args.len() != 4 {
                    false
                } else {
                    match args[3] {
                        "y" => true,
                        "n" => false,
                        _ => {
                            eprintln!("last argument must be y|n");
                            return;
                        }
                    }
                };
                let n_bytes = match args[2].parse::<usize>() {
                    Ok(n) => n,
                    Err(e) => {
                        eprintln!("{}", e);
                        return;
                    }
                };
                let mut buf = vec![0; n_bytes];
                let mut n_read = 0;

                match args[1].parse::<u8>() {
                    Ok(sid) => {
                        while n_read < n_bytes {
                            let n_to_read = n_bytes - n_read;
                            n_read += match self.tcp_module.v_read(
                                sid,
                                &mut buf[n_read..(n_read + n_to_read)],
                                n_to_read,
                            ) {
                                Ok(n) => n,
                                Err(e) => {
                                    eprintln!("{}", e);
                                    return;
                                }
                            };
                            if !block {
                                break;
                            }
                        }
                        let data = String::from_utf8_lossy(&buf).into_owned();
                        let (src_sock, dst_sock) = self.tcp_module.get_sock_entry(sid).unwrap();
                        println!("[{}] Read from {}: \'{}\'", src_sock, dst_sock, data);
                    }
                    Err(e) => eprintln!("{}", e),
                }
            }
            "sf" => {
                if args.len() != 4 {
                    eprintln!("Usage: \"sf <filename> <ip> <port>\"");
                    return;
                }

                let filename = String::from(args[1]);
                let addr = match str_2_ipv4(args[2]) {
                    Ok(addr) => addr,
                    Err(e) => {
                        eprintln!("{e}");
                        return;
                    }
                };
                let port = match args[3].parse::<u16>() {
                    Ok(p) => p,
                    Err(e) => {
                        eprintln!("{e}");
                        return;
                    }
                };

                let tcp_module = self.tcp_module.clone();
                // spawn thread to send file
                thread::spawn(move || {
                    if let Some((elapsed, total_bytes)) =
                        tcp_module.send_file(addr, port, filename.clone())
                    {
                        println!("Sent {total_bytes}B from {filename} to {addr}:{port}!");
                        println!("Time elapsed: {:?}", elapsed);
                    }
                });
            }
            "rf" => {
                if args.len() != 3 {
                    eprintln!("Usage: \"rf <filename> <port>\"");
                    return;
                }

                let filename = String::from(args[1]);
                let port = match args[2].parse::<u16>() {
                    Ok(p) => p,
                    Err(e) => {
                        eprintln!("{e}");
                        return;
                    }
                };

                let tcp_module = self.tcp_module.clone();
                // create thread to receive file
                thread::spawn(move || {
                    if let Some((elapsed, total_bytes)) =
                        tcp_module.recv_file(port, filename.clone())
                    {
                        println!("Received {total_bytes}B into {filename} from 0.0.0.0:{port}!");
                        println!("Time elapsed: {:?}", elapsed);
                    }
                });
            }
            "sd" => {
                if args.len() != 2 && args.len() != 3 {
                    eprintln!("Usage: \"sd <id> <read|write|both>\"");
                    return;
                }
                let sd_type = if args.len() == 2 {
                    ShutdownType::Write
                } else {
                    match args[2] {
                        "read" | "r" => ShutdownType::Read,
                        "write" | "w" => ShutdownType::Write,
                        "both" => ShutdownType::Both,
                        _ => {
                            eprintln!("Last argument must be <read|write|both>.");
                            return;
                        }
                    }
                };

                match args[1].parse::<u8>() {
                    Ok(sid) => {
                        if let Err(e) = self.tcp_module.v_shutdown(sid, sd_type) {
                            eprintln!("{}", e);
                        }
                    }
                    Err(e) => eprintln!("{}", e),
                }
            }
            "cl" => {
                if args.len() != 2 {
                    eprintln!("Usage: \"cl <id>\"");
                    return;
                }
                match args[1].parse::<u8>() {
                    Ok(sid) => {
                        if let Err(e) = self.tcp_module.v_close(sid) {
                            eprintln!("{e}");
                        }
                    }
                    Err(e) => eprintln!("{e}"),
                }
            }
            "down" => {
                if args.len() != 2 {
                    eprintln!("Usage: \"down <id>\"");
                    return;
                }
                match args[1].parse::<isize>() {
                    Ok(id) => match self.ip_module.interface_link_down(id) {
                        Ok(_) => println!("interface {} is now disabled", id),
                        Err(e) => eprintln!("{}", e),
                    },
                    Err(_) => eprintln!("Invalid syntax. Usage: \"down <id>\""),
                }
            }
            "up" => {
                if args.len() != 2 {
                    eprintln!("Usage: \"up <id>\"");
                    return;
                }
                match args[1].parse::<isize>() {
                    Ok(id) => match self.ip_module.interface_link_up(id, self.trigger.clone()) {
                        Ok(_) => println!("interface {} is now enabled", id),
                        Err(e) => eprintln!("{}", e),
                    },
                    Err(_) => eprintln!("Invalid syntax. Usage: \"up <id>\""),
                }
            }
            "send" => {
                if args.len() < 4 {
                    eprintln!("Usage: \"send <ip> <protocol> <payload...>");
                    return;
                }
                // collect payload
                let payload = args[3..].to_vec().join(" ");
                match args[2].parse::<u8>() {
                    Ok(protocol) => match self.send_data(args[1].to_string(), protocol, payload) {
                        Ok(_) => (),
                        Err(e) => eprintln!("{}", e),
                    },
                    Err(_) => {
                        eprintln!("Invalid syntax. Usage: \"send <ip> <protocol> <payload...>")
                    }
                }
            }
            "quit" | "q" => {
                self.quit();
                process::exit(0);
            }
            "log" => {
                if args.len() != 2 {
                    eprintln!("Usage: \"log <socket id>\"");
                    return;
                }
                let sid = match args[1].parse::<u8>() {
                    Ok(id) => id,
                    Err(e) => {
                        eprintln!("{}", e);
                        return;
                    }
                };
                if let Err(e) = self.tcp_module.log_socket_buffers(sid) {
                    eprintln!("{}", e);
                }
            }
            "sf_benchmark" => {
                if args.len() != 5 {
                    eprintln!("Usage: \"sf_benchmark <filename> <ip> <port> <n>\"");
                    return;
                }

                let filename = String::from(args[1]);
                let addr = match str_2_ipv4(args[2]) {
                    Ok(addr) => addr,
                    Err(e) => {
                        eprintln!("{e}");
                        return;
                    }
                };
                let port = match args[3].parse::<u16>() {
                    Ok(p) => p,
                    Err(e) => {
                        eprintln!("{e}");
                        return;
                    }
                };
                let n = match args[4].parse::<usize>() {
                    Ok(n) => n,
                    Err(e) => {
                        eprintln!("{e}");
                        return;
                    }
                };

                // record results
                let mut result_str = String::from("Results: \n");
                let mut total_time = Duration::ZERO;
                let mut n_bytes = 0;
                let mut n_successful = n;
                let start = Instant::now();

                let start_str = format!("Starting sendfile benchmark (sending \"{filename}\" {n} times to {addr}:{port})...");
                println!("{}", start_str);
                let tcp_module = self.tcp_module.clone();
                // spawn thread to run in background
                thread::spawn(move || {
                    for i in 0..n {
                        if let Some((elapsed, total_bytes)) =
                            tcp_module.send_file(addr, port, filename.clone())
                        {
                            result_str.push_str(&format!(
                                " [{}] Time elapsed: {:?}",
                                i + 1,
                                elapsed
                            ));
                            // check if SYN failed to connect
                            if total_bytes == 0 {
                                result_str.push_str(" [FAILED THREE-WAY HANDSHAKE]");
                                n_successful -= 1;
                            }
                            // pretty formatting
                            if i != n - 1 {
                                result_str.push('\n');
                            }

                            total_time += elapsed;
                            n_bytes += total_bytes;

                            // sleep for 500ms, to give the receiving end time to cleanup and make
                            // new socket
                            thread::sleep(Duration::from_millis(500));
                        } else {
                            println!("The {}th send failed. Halting early...", i + 1);
                            break;
                        }
                    }
                    let n_mb = n_bytes / 1_000_000;
                    let stats = format!(
                        "Average time: {:?}\tTotal sent: {}MB\tRate: {:.4}[B/s]",
                        total_time.div_f64(n_successful as f64),
                        n_mb,
                        (n_bytes as f64) / total_time.as_secs_f64()
                    );

                    // display results
                    println!("{}", result_str);
                    println!("{}", stats);
                    println!("Total elapsed time: {:?}", start.elapsed());

                    // log to file
                    let time_str = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap()
                        .as_secs();
                    let results_file = format!("{}/send_{}.txt", SEND_BENCHMARKS_DIR, time_str);
                    let mut results_file = File::create(results_file).unwrap();
                    results_file.write_all(start_str.as_bytes()).ok();
                    results_file.write(b"\n").ok();
                    results_file.write_all(result_str.as_bytes()).ok();
                    results_file.write(b"\n").ok();
                    results_file.write_all(stats.as_bytes()).ok();
                });
            }
            "rf_benchmark" => {
                if args.len() != 4 {
                    eprintln!("Usage: \"rf_benchmark <filename> <port> <n>\"");
                    return;
                }

                let filename = String::from(args[1]);
                let port = match args[2].parse::<u16>() {
                    Ok(p) => p,
                    Err(e) => {
                        eprintln!("{e}");
                        return;
                    }
                };
                let n = match args[3].parse::<usize>() {
                    Ok(n) => n,
                    Err(e) => {
                        eprintln!("{e}");
                        return;
                    }
                };

                // record results
                let mut result_str = String::from("Results: \n");
                let mut total_time = Duration::ZERO;
                let mut n_bytes = 0;
                let start = Instant::now();

                println!("Starting recvfile benchmark (receiving {n} files on port {port})...");
                let tcp_module = self.tcp_module.clone();
                // spawn thread to run in background
                thread::spawn(move || {
                    for i in 0..n {
                        let out_file = format!("{}_{}", filename, i);
                        if let Some((elapsed, total_bytes)) =
                            tcp_module.recv_file(port, out_file.clone())
                        {
                            result_str.push_str(&format!(
                                " [{}] Time elapsed: {:?} [out file: {}]",
                                i + 1,
                                elapsed,
                                out_file
                            ));
                            // check if SYN failed to connect
                            if total_bytes == 0 {
                                result_str.push_str(" [FAILED THREE-WAY HANDSHAKE]");
                            }
                            // pretty formatting
                            if i != n - 1 {
                                result_str.push('\n');
                            }

                            total_time += elapsed;
                            n_bytes += total_bytes;
                        } else {
                            println!("The {}th recv failed. Halting early...", i + 1);
                            break;
                        }
                    }
                    let n_mb = n_bytes / 1_000_000;
                    let stats = format!(
                        "Average time: {:?}\tTotal received: {}MB\tRate: {:.4}B/s",
                        total_time.div_f64(n as f64),
                        n_mb,
                        (n_bytes as f64) / total_time.as_secs_f64()
                    );

                    // display results
                    println!("{}", result_str);
                    println!("{}", stats);
                    println!("Total elapsed time: {:?}", start.elapsed());
                });
            }
            "" => (),
            _ => eprintln!("Error: command not found. Help menu:\n{}", HELP_MSG),
        }
    }

    /**
     * Send data with specified protocol.
     */
    pub fn send_data(&self, ip: String, protocol: u8, payload: String) -> Result<()> {
        let dst_addr = str_2_ipv4(&ip)?;

        // find local interface and check if one of the destinations
        if let Some(route) = self.ip_module.routing_table.get_route(&dst_addr) {
            self.ip_module.handle_ip(IPPacket::new(
                route.gateway,
                dst_addr,
                payload.as_bytes().into(),
                DEFAULT_TTL + 1, // + 1 due to how handle_ip works; maybe call send_ip instead
                protocol,
            ));
            Ok(())
        } else {
            Err(Error::new(ErrorKind::Other, "Destination not reachable!"))
        }
    }
}

/**
 * Helper function to read all lines of a file specified by the path filename.
 */
fn read_lines<P>(filename: P) -> Result<Lines<BufReader<File>>>
where
    P: AsRef<Path>,
{
    let file = File::open(filename)?;
    Ok(BufReader::new(file).lines())
}

/**
 * Converts a string into an IP address.
 */
fn str_2_ipv4(s: &str) -> Result<Ipv4Addr> {
    if s == "localhost" {
        Ok(Ipv4Addr::LOCALHOST)
    } else {
        match s.parse::<Ipv4Addr>() {
            Ok(ip) => Ok(ip),
            Err(_) => Err(Error::new(ErrorKind::Other, "invalid IP address")),
        }
    }
}

const HELP_MSG: &str = " ==================== General node information ====================
 help (h)        : Print this list of commands.
 interfaces (li) : Print information about each interface, one per line.
 routes (lr)     : Print information about the route to each known destination, one per line.
 quit (q)        : Quit this node, closing all open sockets.

 ==================== Socket creation/shutdown ====================
 sockets (ls)    : Print information about each socket (ID, IP, Port, State).
 a [port]        : Spawn a socket, bind it to the given port, and start accepting connections on that port.
 c [ip] [port]   : Attempt to connect to the given ip address, in dot notation, on the given port.
 sd [id] [read|write|both]: Shutdown a socket. \"read\"/\"r\" closes only the reading side; \"write\"/\"w\"
                            closes only the writing side; \"both\" closes both. Default is \"write\".
 cl [id]: v_close on the given socket.

 ==================== Data transmission commands ====================
 s [sid] [data]  : Send a string to a socket. Blocks until v_write() returns.
 r [sid] [n_bytes] [y|n]: Try to read data from a socket. If last argument \"y\", blocks until n_bytes are
                          read or connection closes. If \"n\" (default), returns whenever v_read() returns.
 sf [filename] [ip] [port]: Connect to the given IP and port, send the entirety of the specified file, and
                            close the connection.
 rf [filename] [port]: Listen for a connection on the given port. Once established, write everything you can
                       read from the socket to the given file. Once the other side closes the connection, close
                       the connection as well.

 ==================== IP/network commands ====================
 send [ip] [protocol] [payload] : sends payload with the specified protocol to the virtual IP address.
 up [integer]   : Bring an interface \"up\" (it must be an existing interface, probably one you brought down).
 down [integer] : Bring an interface \"down\".

 ==================== Logging commands ====================
 log [id]: print SendControlBuffer and RecvControlBuffer information about socket with the specified id.
 sf_benchmark [filename] [ip] [port] [n]: Send a file to the destination socket n times, then display benchmarks.
 rf_benchmark [filename] [port] [n]: Receive a file on the provided port n times, then display benchmarks.
 ";
