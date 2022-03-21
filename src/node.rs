mod protocol;

pub struct Node {
    interfaces: Vec<protocol::network::NetworkInterface>,
    routes: HashMap<protocol::network::NetworkInterface, usize>,
}
