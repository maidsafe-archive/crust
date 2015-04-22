// Copyright 2015 MaidSafe.net limited
//
// This MaidSafe Software is licensed to you under (1) the MaidSafe.net Commercial License,
// version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
// licence you accepted on initial access to the Software (the "Licences").
//
// By contributing code to the MaidSafe Software, or to this project generally, you agree to be
// bound by the terms of the MaidSafe Contributor Agreement, version 1.0, found in the root
// directory of this project at LICENSE, COPYING and CONTRIBUTOR respectively and also
// available at: http://www.maidsafe.net/licenses
//
// Unless required by applicable law or agreed to in writing, the MaidSafe Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS
// OF ANY KIND, either express or implied.
//
// See the Licences for the specific language governing permissions and limitations relating to
// use of the MaidSafe Software.

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6, UdpSocket};
use std::sync::mpsc::{Sender, Receiver};
use std::sync::mpsc;
use std::thread;

pub fn serialise_address(our_listening_address: SocketAddr) -> [u8; 27] {
    let mut our_details = [0u8; 27];
    match our_listening_address {
        SocketAddr::V4(ref v4_address) => {
            // Leave first byte as 0 to indicate IPv4
            for i in 0..4 {
                our_details[i + 1] = v4_address.ip().octets()[i];
            }
            our_details[5] = (v4_address.port() >> 8) as u8;
            our_details[6] = v4_address.port() as u8;
        },
        SocketAddr::V6(ref v6_address) => {
            // Set first byte as 1 to indicate IPv6
            our_details[0] = 1u8;
            for i in 0..8 {
                our_details[(2 * i) + 1] = (v6_address.ip().segments()[i] >> 8) as u8;
                our_details[(2 * i) + 2] = v6_address.ip().segments()[i] as u8;
            }
            our_details[17] = (v6_address.port() >> 8) as u8;
            our_details[18] = v6_address.port() as u8;
            our_details[19] = (v6_address.flowinfo() >> 24) as u8;
            our_details[20] = (v6_address.flowinfo() >> 16) as u8;
            our_details[21] = (v6_address.flowinfo() >> 8) as u8;
            our_details[22] = v6_address.flowinfo() as u8;
            our_details[23] = (v6_address.scope_id() >> 24) as u8;
            our_details[24] = (v6_address.scope_id() >> 16) as u8;
            our_details[25] = (v6_address.scope_id() >> 8) as u8;
            our_details[26] = v6_address.scope_id() as u8;
        },
    }
    our_details
}

pub fn parse_address(buffer: &[u8]) -> Option<SocketAddr> {
    match buffer[0] {
        0 => {
            let port: u16 = ((buffer[5] as u16) * 256) + (buffer[6] as u16);
            let peer_socket = SocketAddrV4::new(Ipv4Addr::new(
                buffer[1], buffer[2], buffer[3], buffer[4]), port);
            println!("Received IPv4 address {:?}\n", peer_socket);
            Some(SocketAddr::V4(peer_socket))
        },
        1 => {
            let mut segments = [0u16; 8];
            for i in 0..8 {
                segments[i] =
                    ((buffer[(2 * i) + 1] as u16) << 8) + (buffer[(2 * i) + 2] as u16);
            }
            let port: u16 = ((buffer[17] as u16) << 8) + (buffer[18] as u16);
            let flowinfo: u32 =
                ((buffer[19] as u32) << 24) + ((buffer[20] as u32) << 16) +
                ((buffer[21] as u32) << 8) + (buffer[22] as u32);
            let scope_id: u32 =
                ((buffer[23] as u32) << 24) + ((buffer[24] as u32) << 16) +
                ((buffer[25] as u32) << 8) + (buffer[26] as u32);
            let peer_socket = SocketAddrV6::new(Ipv6Addr::new(
                segments[0], segments[1], segments[2], segments[3], segments[4],
                segments[5], segments[6], segments[7]), port, flowinfo, scope_id);
            println!("Received IPv6 address {:?} with flowinfo {} and scope_id {}\n",
                      peer_socket, flowinfo, scope_id);
            Some(SocketAddr::V6(peer_socket))
        },
        _ => None,
    }
}

fn handle_receive(socket: &UdpSocket) -> Option<SocketAddr> {
    let mut buffer = [0; 27];
    match socket.recv_from(&mut buffer) {
        Ok((received_length, source)) => {
            assert_eq!(27, received_length);
            parse_address(&buffer)
        }
        Err(e) => {
            println!("Failed receiving a message: {}", e);
            None
        }
    }
}

pub fn listen_for_broadcast(our_listening_address: SocketAddr) {
    let socket = match UdpSocket::bind("0.0.0.0:5483") {
        Ok(bound_socket) => bound_socket,
        Err(error) => panic!("Couldn't bind socket: {}", error),
    };

    let our_serialised_details = serialise_address(our_listening_address);

    loop {
        let mut buffer = [0; 4];
        match socket.recv_from(&mut buffer) {
            Ok((received_length, source)) => {
                let _ = socket.send_to(&our_serialised_details, source);
            }
            Err(error) => println!("Failed receiving a message: {}", error)
        }
    }
}

pub fn seek_peers() -> Vec<SocketAddr> {
    let socket = match UdpSocket::bind("0.0.0.0:0") {
        Ok(s) => s,
        Err(e) => panic!("Couldn't bind socket: {}", e),
    };

    match socket.set_broadcast(true) {
        Ok(s) => s,
        Err(e) => panic!("Can't broadcast from this socket: {}", e),
    }

    let buffer = [0; 4];
    match socket.send_to(&buffer, ("255.255.255.255:5483")) {
        Ok(s) => assert_eq!(4, s),
        Err(e) => panic!("Failed broadcasting on {}: {}", socket.local_addr().unwrap(), e),
    }
    println!("Broadcasted on {:?}", socket.local_addr().unwrap());

    let (tx, rx): (Sender<SocketAddr>, Receiver<SocketAddr>) = mpsc::channel();
    thread::spawn(move || {
        loop {
            match handle_receive(&socket) {
                Some(peer_address) => tx.send(peer_address).unwrap(),
                _ => (),
            }
        }
    });

    // Allow peers time to respond
    thread::sleep_ms(500);

    let mut peers: Vec<SocketAddr> = Vec::new();
    let mut result = rx.try_recv();
    while let Ok(res) = result {
        peers.push(res);
        result = rx.try_recv();
    }

    peers
}



#[cfg(test)]
mod test {
    use super::*;
    use std::net::{UdpSocket/*, lookup_addr, lookup_host*/};
    use std::thread;

#[test]
    fn test_broadcast() {
        // Start a normal socket and start listening for a broadcast
        thread::spawn(move || {
            let normal_socket = match UdpSocket::bind("::0:0") {
                Ok(s) => s,
                Err(e) => panic!("Couldn't bind socket: {}", e),
            };
            println!("Normal socket on {:?}\n", normal_socket.local_addr().unwrap());
            listen_for_broadcast(normal_socket.local_addr().unwrap());
        });

        // Allow listener time to start
        thread::sleep_ms(300);

        for i in 0..3 {
            let peers = seek_peers();
            assert!(peers.len() > 0);
        }
    }
}
