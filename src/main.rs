mod node;
mod protocol;

use clap::Parser;
use node::*;
extern crate shrust;
use shrust::{Shell, ShellIO};
use std::io::{prelude::*, Error};
use std::process;
use std::sync::{Arc, Mutex};

use crate::protocol::network::{rip::*, *};

#[derive(Parser)]
struct Args {
    linksfile: String,
}

// TODO: REMOVE THIS IS JUST A TEST
fn rip_handler(packet: IPPacket) -> Result<(), Error> {
    let msg = recv_rip_message(&packet);
    println!("Message: {:?}", msg);
    Ok(())
}

fn main() {
    let args = Args::parse();

    let ph = ProtocolHandler {
        protocol: RIP_PROTOCOL,
        handler: Arc::new(Mutex::new(rip_handler)),
    };

    // Attempt to make a node
    let node = match Node::new(args.linksfile, vec![ph]) {
        Ok(node) => node,
        Err(e) => {
            eprintln!("{}", e);
            process::exit(1);
        }
    };

    // node.register_handler(
    // RIP_PROTOCOL,
    // make_rip_handler(node.get_interfaces(), node.get_routing_table()),
    // );

    let mut shell = Shell::new(node);
    shell.new_command_noargs("help", "Print this list of commands", |io, _| {
        writeln!(io, "{}", HELP_MSG)?;
        Ok(())
    });

    shell.new_command_noargs("h", "Print this list of commands", |io, _| {
        writeln!(io, "{}", HELP_MSG)?;
        Ok(())
    });

    shell.new_command_noargs(
        "interfaces",
        "Print information about each interface, one per line",
        |io, node| {
            // let node = node.lock().unwrap();
            writeln!(io, "{}", node.fmt_interfaces())?;
            Ok(())
        },
    );
    shell.new_command_noargs("li", "See interfaces", |io, node| {
        // let node = node.lock().unwrap();
        writeln!(io, "{}", node.fmt_interfaces())?;
        Ok(())
    });

    shell.new_command_noargs(
        "routes",
        "Print information about the route to each known destination, one per line",
        |io, node| {
            // let node = node.lock().unwrap();
            writeln!(io, "{}", node.fmt_routes())?;
            Ok(())
        },
    );

    shell.new_command_noargs("lr", "See routes", |io, node| {
        // let node = node.lock().unwrap();
        writeln!(io, "{}", node.fmt_routes())?;
        Ok(())
    });

    shell.new_command_noargs("q", "Quit this node", |_, _| {
        process::exit(0);
    });

    shell.new_command("down", "Bring an interface “down”", 1, |io, node, s| {
        // let mut node = node.lock().unwrap();
        match s[0].parse::<isize>() {
            Ok(id) => match node.interface_link_down(id) {
                Err(err) => {
                    writeln!(io, "{}", err)?;
                }
                Ok(()) => {
                    writeln!(io, "interface {} is now disabled", id)?;
                }
            },
            Err(_) => writeln!(io, "syntax error (usage: down [interface])")?,
        }
        Ok(())
    });

    shell.new_command("up", "Bring an interface “up”", 1, |io, node, s| {
        // let mut node = node.lock().unwrap();
        match s[0].parse::<isize>() {
            Ok(id) => match node.interface_link_up(id) {
                Err(err) => {
                    writeln!(io, "{}", err)?;
                }
                Ok(()) => {
                    writeln!(io, "interface {} is now enabled", id)?;
                }
            },
            Err(_) => writeln!(io, "syntax error (usage: up [interface])")?,
        }
        Ok(())
    });

    shell.new_command("send", "Send an IP packet", 3, |io, _, s| {
        writeln!(io, "Send {}", s[0])?;
        Ok(())
    });

    shell.set_default(|io, _, _| {
        writeln!(io, "Error: command not found. Help menu:\n{}", HELP_MSG)?;
        Ok(())
    });

    shell.run_loop(&mut ShellIO::default());
}

const HELP_MSG: &str = " help       : Print this list of commands
 h          : See help
 interfaces : Print information about each interface, one per line
 li         : See interfaces
 routes     : Print information about the route to each known destination, one per line
 lr         : See routes
 q          : Quit this node

 send [ip] [protocol] [payload] : sends payload with protocol=protocol to virtual-ip ip
 up [integer]   : Bring an interface \"up\" (it must be an existing interface, probably one you brought down)
 down [integer] : Bring an interface \"down\"
 ";
