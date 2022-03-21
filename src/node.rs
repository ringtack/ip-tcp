use crate::protocol::network::NetworkInterface;
use std::collections::HashMap;

pub struct Node {
    interfaces: Vec<NetworkInterface>,
    routes: HashMap<NetworkInterface, usize>,
}
