mod node;
mod protocol;
use clap::Parser;
use node::Node;
use std::env;
extern crate shrust;
use shrust::{Shell, ShellIO};
use std::io::prelude::*;

#[derive(Parser)]
struct Cli {
    linksfile: String,
}

fn main() {
    let args = Cli::parse();
    //TODO read and parse linksfile here

    let mut shell = Shell::new(());

    // let node = Node::new(5);
    shell.new_command_noargs(
        "interfaces",
        "Print information about each interface, one per line",
        |io, _| {
            writeln!(io, "interfaces")?;
            Ok(())
        },
    );
    shell.new_command_noargs("li", "See interfaces", |io, _| {
        writeln!(io, "interfaces")?;
        Ok(())
    });

    shell.new_command_noargs(
        "routes",
        "Print information about the route to each known destination, one per line",
        |io, _| {
            writeln!(io, "routes")?;
            Ok(())
        },
    );

    shell.new_command_noargs("lr", "See routes", |io, _| {
        writeln!(io, "routes")?;
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
