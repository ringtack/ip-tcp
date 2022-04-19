use crate::protocol::link::READ_TIMEOUT;
use crate::protocol::network::{
    ip_packet::*, network_interfaces::*, rip::*, routing_table::*, test::*, InternetModule,
};
use crate::protocol::tcp::{tcp_socket::*, *};

use std::{
    collections::HashMap,
    fs::File,
    io::{BufRead, BufReader, Error, ErrorKind, Lines, Result},
    net::{Ipv4Addr, SocketAddrV4, UdpSocket},
    path::Path,
    process,
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc::{channel, Sender},
        Arc,
    },
    thread,
    time::{Duration, Instant},
};

/**
 * Struct representing the network layer interface.
 */
pub struct Node {
    ip_module: InternetModule,
    tcp_layer: TCPLayer,
    trigger: Sender<Ipv4Addr>,
    threads: Vec<thread::JoinHandle<()>>,
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
        // Create initial structs for Node construction
        let ifs = Arc::new(ifs);
        let rt = Arc::new(rt);
        let stopped = Arc::new(AtomicBool::new(false));
        // create sender and receiver for trigger updates
        let (tx, rx) = channel::<Ipv4Addr>();

        /* ====================================================================
         * Protocol Handlers Setup
         * ====================================================================
         */
        let mut handlers = HashMap::new();
        handlers.insert(TEST_PROTOCOL, make_test_handler(ifs.clone()));
        handlers.insert(
            RIP_PROTOCOL,
            make_rip_handler(ifs.clone(), rt.clone(), tx.clone()),
        );
        let handlers = Arc::new(handlers);

        let ip_module = InternetModule::new(rt.clone(), ifs.clone(), handlers);
        // create Node!
        let mut node = Node {
            ip_module: ip_module.clone(),
            tcp_layer: TCPLayer::new(ip_module),
            trigger: tx.clone(),
            threads: Vec::new(),
            stopped: stopped.clone(),
        };

        /* ====================================================================
         * Thread Handlers Setup
         * ====================================================================
         */
        // set up cleanup thread in RoutingTable
        node.threads
            .push(RoutingTable::make_rt_cleanup(rt, tx, stopped.clone()));

        // set up trigger response thread
        node.threads
            .push(node.ip_module.make_trigger_response(rx, stopped.clone()));

        // set up periodic RIP update thread
        node.threads
            .push(node.ip_module.make_periodic_updates(stopped.clone()));

        // let ifs = ifs.read().unwrap();
        // send initial RIP Request to network interfaces (i.e. neighbors)
        for dest_if in ifs.iter() {
            send_rip_message(dest_if, RIPMessage::new(RIP_REQUEST, 0, vec![]))?;
        }
        // mem::drop(ifs);

        // Set up packet listener thread
        node.threads
            .push(node.ip_module.clone().make_ip_listener(stopped));

        // print out startup interfaces
        println!("{}", node.ip_module.fmt_startup_interfaces());

        Ok(node)
    }

    /**
     * Gracefully exit the node.
     */
    pub fn quit(&mut self) {
        // notify all threads that we're done by updating stopped flag
        self.stopped.store(true, Ordering::Relaxed);

        // join all threads
        while let Some(cur_thr) = self.threads.pop() {
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
            "down" => {
                if args.len() != 2 {
                    eprintln!("Usage: \"down <id>\"");
                } else {
                    match args[1].parse::<isize>() {
                        Ok(id) => match self.ip_module.interface_link_down(id) {
                            Ok(_) => println!("interface {} is now disabled", id),
                            Err(e) => eprintln!("{}", e),
                        },
                        Err(_) => eprintln!("Invalid syntax. Usage: \"down <id>\""),
                    }
                }
            }
            "up" => {
                if args.len() != 2 {
                    eprintln!("Usage: \"up <id>\"");
                } else {
                    match args[1].parse::<isize>() {
                        Ok(id) => {
                            match self.ip_module.interface_link_up(id, self.trigger.clone()) {
                                Ok(_) => println!("interface {} is now enabled", id),
                                Err(e) => eprintln!("{}", e),
                            }
                        }
                        Err(_) => eprintln!("Invalid syntax. Usage: \"up <id>\""),
                    }
                }
            }
            "send" => {
                if args.len() < 4 {
                    eprintln!("Usage: \"send <ip> <protocol> <payload...>");
                } else {
                    // collect payload
                    let payload = args[3..].to_vec().join(" ");
                    match args[2].parse::<u8>() {
                        Ok(protocol) => {
                            match self.send_data(args[1].to_string(), protocol, payload) {
                                Ok(_) => (),
                                Err(e) => eprintln!("{}", e),
                            }
                        }
                        Err(_) => {
                            eprintln!("Invalid syntax. Usage: \"send <ip> <protocol> <payload...>")
                        }
                    }
                }
            }
            "quit" | "q" => {
                self.quit();
                process::exit(0);
            }
            _ => eprintln!("Error: command not found. Help menu:\n{}", HELP_MSG),
        }
    }

    /**
     * Send data with specified protocol.
     */
    pub fn send_data(&self, ip: String, protocol: u8, payload: String) -> Result<()> {
        let dst_addr = str_2_ipv4(&ip)?;

        // find local interface
        // let routing_table = self.ip_module.routing_table.lock().unwrap();
        // check if one of the destinations
        if let Some(route) = self.ip_module.routing_table.get_route(&dst_addr) {
            // mem::drop(routing_table);
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

const HELP_MSG: &str = " help (h)        : Print this list of commands
 interfaces (li) : Print information about each interface, one per line
 routes (lr)     : Print information about the route to each known destination, one per line
 quit (q)        : Quit this node

 send [ip] [protocol] [payload] : sends payload with protocol=protocol to virtual-ip ip
 up [integer]   : Bring an interface \"up\" (it must be an existing interface, probably one you brought down)
 down [integer] : Bring an interface \"down\"
 ";
