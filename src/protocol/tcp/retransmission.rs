/**
 * Handles all retransmissions
 *
 * Inputs:
 * - segment_rx: receiver of incoming segments.
 * - sockets: copy of socket table
 * - pending_socks: set of all sockets with pending operation
 *
 * Returns:
 * - 
 */
pub fn check_retransmission(
    sockets: SocketTable,
    pending_socks: Arc<DashSet<SocketEntry>>,
)-> thread::JoinHandle<()> {
    thread::spawn(move || {
        loop {
            // iterate pending_socks

            // check => time => if timeout => retransmit


            thread::sleep(1);   
        }
    }
}