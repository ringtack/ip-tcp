mod node;
mod protocol;

use node::*;
use std::env::args;
use std::process;

use rustyline::error::ReadlineError;
use rustyline::Editor;

fn main() {
    let linksfile = args().nth(1).expect("Usage: ./node <linksfile>\n");

    // Attempt to make a node
    let mut node = match Node::new(linksfile) {
        Ok(node) => node,
        Err(e) => {
            eprintln!("{}", e);
            process::exit(1);
        }
    };

    // configure readline interface
    let mut rl = Editor::<()>::new();
    loop {
        // accept input
        match rl.readline("> ") {
            Ok(line) => {
                // add line to history
                rl.add_history_entry(line.as_str());
                // handle command
                node.handle_command(&line.split(' ').collect::<Vec<&str>>());
            }
            // on Ctrl-C, force exit
            Err(ReadlineError::Interrupted) => {
                process::exit(1);
            }
            // On Ctrl-D, exit gracefully
            Err(ReadlineError::Eof) => {
                node.quit();
                break;
            }
            Err(err) => {
                println!("Error: {:?}", err);
            }
        }
    }
}
