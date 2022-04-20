use super::*;
use bimap::BiMap;

#[derive(Clone)]
pub struct SocketTable {
    socket_ids: Arc<RwLock<BiMap<SocketID, SocketEntry>>>,
    sockets: Arc<DashMap<SocketEntry, Socket>>,
}

impl SocketTable {
    pub fn new() -> SocketTable {
        SocketTable {
            socket_ids: Arc::new(RwLock::new(BiMap::new())),
            sockets: Arc::new(DashMap::new()),
        }
    }

    pub fn len(&self) -> usize {
        self.sockets.len()
    }

    /**
     * Inserts a (socket id, socket entry, socket) into the table.
     */
    pub fn insert_entry(&self, sid: SocketID, sock_entry: SocketEntry, socket: Socket) {
        let mut socket_ids = self.socket_ids.write().unwrap();
        socket_ids.insert(sid, sock_entry.clone());
        self.sockets.insert(sock_entry, socket);
    }

    /**
     * Checks whether a given entry is in the socket table.
     */
    pub fn has_entry(&self, sock_entry: &SocketEntry) -> bool {
        self.sockets.contains_key(sock_entry)
    }

    /**
     * Gets a socket ID with the specified (src_sock, dst_sock) pair.
     *
     * Inputs:
     * - sock_entry: the socket entry with the src_sock, dst_sock pair
     *
     * Returns:
     * - the socket ID if present, or None otherwise
     */
    pub fn get_socket_id(&self, sock_entry: &SocketEntry) -> Option<SocketID> {
        let socket_ids = self.socket_ids.read().unwrap();
        socket_ids.get_by_right(sock_entry).copied()
    }

    /**
     * Gets a socket entry with the specified socket ID.
     *
     * Inputs:
     * - sid: the socket ID of the desired socket entry
     *
     * Returns:
     * - the socket entry if present, or None otherwise
     */
    pub fn get_socket_entry(&self, sid: SocketID) -> Option<SocketEntry> {
        let socket_ids = self.socket_ids.read().unwrap();
        socket_ids.get_by_left(&sid).cloned()
    }

    /**
     * Gets the socket associated with the socket id.
     *
     * Inputs:
     * - sid: the socket ID of the desired socket
     *
     * Returns:
     * - the socket entry if present, or None otherwise
     */
    pub fn get_socket_by_id(&self, sid: SocketID) -> Option<Socket> {
        let socket_ids = self.socket_ids.read().unwrap();
        match socket_ids.get_by_left(&sid) {
            Some(sock_entry) => self.sockets.get(sock_entry).map(|se| se.value().clone()),
            None => None,
        }
    }

    /**
     * Gets the socket associated with the socket entry.
     *
     * Inputs:
     * - sock_entry: the socket entry of the desired socket
     *
     * Returns:
     * - the socket entry if present, or None otherwise
     */
    pub fn get_socket_by_entry(&self, sock_entry: &SocketEntry) -> Option<Socket> {
        self.sockets.get(sock_entry).map(|se| se.value().clone())
    }

    /*
     * Gets a mutable reference to the socket associatede with the socket entry.
     *
     * Inputs:
     * - sock_entry: the socket entry of the desired socket
     *
     * Returns:
     * - the socket entry if present, or None otherwise
     */
    // pub fn get_socket_mut(&self, sock_entry: &SocketEntry) -> Option<&mut Socket> {
    // self.sockets
    // .get_mut(sock_entry)
    // .map(|mut se| se.value_mut())
    // }

    /**
     * Deletes the socket associated with the socket entry. YOU ARE RESPONSIBLE FOR CLEANING
     * EVERYTHING ELSE UP! [TODO: perhaps change this so this cleans up]
     */
    pub fn delete_socket_by_entry(&self, sock_entry: &SocketEntry) {
        self.sockets.remove(sock_entry);
    }

    /**
     * Gets an iterator to the socket table.
     */
    pub fn iter(&self) -> Iter<'_, SocketEntry, Socket> {
        self.sockets.iter()
    }
}
