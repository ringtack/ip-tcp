mod node;
mod protocol;

use clap::Parser;
use node::Node;
extern crate shrust;
use shrust::{Shell, ShellIO};
use std::env;
use std::io::prelude::*;
use std::process;

#[derive(Parser)]
struct Args {
    linksfile: String,
}

fn main() {
    let args = Args::parse();
    let node = node::Node::new(args.linksfile);
    if let Err(e) = node {
        eprintln!("{}", e);
        process::exit(1);
    }
    //TODO read and parse linksfile here

    let mut shell = Shell::new(node.unwrap());
    shell.new_command_noargs(
        "interfaces",
        "Print information about each interface, one per line",
        |io, node| {
            writeln!(io, "{}", node.fmt_interfaces())?;
            Ok(())
        },
    );
    shell.new_command_noargs("li", "See interfaces", |io, node| {
        writeln!(io, "{}", node.fmt_interfaces())?;
        Ok(())
    });

    shell.new_command_noargs(
        "routes",
        "Print information about the route to each known destination, one per line",
        |io, node| {
            writeln!(io, "{}", node.fmt_routes())?;
            Ok(())
        },
    );

    shell.new_command_noargs("lr", "See routes", |io, node| {
        writeln!(io, "{}", node.fmt_routes())?;
        Ok(())
    });

    shell.new_command("down", "Bring an interface “down”", 1, |io, _, s| {
        writeln!(io, "Down {}", s[0])?;
        Ok(())
    });

    shell.new_command("up", "Bring an interface “up”", 1, |io, _, s| {
        writeln!(io, "Up {}", s[0])?;
        Ok(())
    });

    shell.new_command("send", "Send an IP packet", 3, |io, _, s| {
        writeln!(io, "Send {}", s[0])?;
        Ok(())
    });

    shell.run_loop(&mut ShellIO::default());
}
