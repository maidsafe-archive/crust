// Copyright 2015 MaidSafe.net limited
//
// This SAFE Network Software is licensed to you under (1) the MaidSafe.net Commercial License,
// version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
// licence you accepted on initial access to the Software (the "Licences").
//
// By contributing code to the SAFE Network Software, or to this project generally, you agree to be
// bound by the terms of the MaidSafe Contributor Agreement, version 1.0, found in the root
// directory of this project at LICENSE, COPYING and CONTRIBUTOR respectively and also
// available at: http://maidsafe.net/network-platform-licensing
//
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS
// OF ANY KIND, either express or implied.
//
// See the Licences for the specific language governing permissions and limitations relating to
// use of the SAFE Network Software.

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6, UdpSocket};
use std::sync::mpsc;
use std::thread;
use std::thread::spawn;
use std::io::Result;
use transport;
use transport::{Port};
use bootstrap::{BootStrapHandler};

const MAGIC: [u8; 4] = ['m' as u8, 'a' as u8, 'i' as u8, 'd' as u8];

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

fn serialise_port(port: u16) -> [u8;2] {
    [(port & 0xff) as u8, (port >> 8) as u8]
}

fn parse_port(data: [u8;2]) -> u16 {
    (data[0] as u16) + ((data[1] as u16) << 8)
}

struct BroadcastAcceptor {
    socket: UdpSocket,
}

impl BroadcastAcceptor {
    pub fn bind(port: u16) -> Result<BroadcastAcceptor> {
        let socket = try!(UdpSocket::bind(("0.0.0.0", port)));
        Ok(BroadcastAcceptor{ socket: socket })
    }

    // FIXME: Proper error handling and cancelation.
    pub fn accept(&self) -> Result<transport::Transport> {
        use transport::{Transport};

        let (port_sender, port_receiver) = mpsc::channel::<u16>();
        let (transport_sender, transport_receiver) = mpsc::channel::<Transport>();

        let run_acceptor = move || -> Result<()> {
            let acceptor = try!(transport::new_acceptor(&Port::Tcp(0)));
            let _ = port_sender.send(try!(transport::local_endpoint(&acceptor)).get_address().port());
            let transport = try!(transport::accept(&acceptor));
            let _ = transport_sender.send(transport);
            Ok(())
        };
        let t1 = thread::spawn(move || { let _ = run_acceptor(); });

        let tcp_port = port_receiver.recv().unwrap(); // We don't expect this to fail.

        let run_listener = move || -> Result<()> {
            let mut buffer = [0u8; 4];
            loop {
                let (_, source) = try!(self.socket.recv_from(&mut buffer));
                if buffer != MAGIC { continue; }
                let reply_socket = try!(UdpSocket::bind("0.0.0.0:0"));
                try!(reply_socket.send_to(&serialise_port(tcp_port), source));
                break;
            }
            Ok(())
        };
        let t2 = thread::scoped(move || { let _ = run_listener(); });

        let _ = t1.join();
        let _ = t2.join();

        Ok(transport_receiver.recv().unwrap())
    }

    fn local_addr(&self) -> Result<SocketAddr> {
        self.socket.local_addr()
    }
}

// NOTE For Fraser: This is the new function, I implemented the old one
// (seek_peers below) using this one.
fn seek_peers_2(port: u16) -> Result<Vec<SocketAddr>> {
    // Send broadcast ping
    let socket = try!(UdpSocket::bind("0.0.0.0:0"));
    try!(socket.set_broadcast(true));
    try!(socket.send_to(&MAGIC, ("255.255.255.255", port)));

    let (tx,rx) = mpsc::channel::<SocketAddr>();

    // FIXME: This thread will never finish, eating one udp port
    // and few resources till the end of the program. I haven't
    // found a way to fix this in rust yet.
    let runner = move || -> Result<()> {
        let mut buffer = [0u8; 2];
        let (size, source) = try!(socket.recv_from(&mut buffer));
        let his_port = parse_port(buffer);
        let his_ep   = SocketAddr::new(source.ip(), his_port);
        tx.send(his_ep);
        Ok(())
    };

    thread::spawn(move || { let _ = runner(); });

    // Allow peers to respond.
    thread::sleep_ms(500);

    let mut result = Vec::<SocketAddr>::new();

    loop {
        match rx.try_recv() {
            Ok(socket_addr) => result.push(socket_addr),
            Err(_) => break,
        }
    }

    Ok(result)
}

// NOTE For Fraser: This one is deprecated now (but this signature is used outside of this module).
// Also note that this new seek_peers function is no longer compatible with the below
// listen_for_broadcast call.
/// Seek for peers, send out beacon to local network on port 5483.
pub fn seek_peers(port: Option<Port>) -> Vec<SocketAddr> {
    let bootstrap_port: u16 = match port {
        Some(port) =>  { match port { Port::Tcp(num) => num }},
        None => 5483
    };

    seek_peers_2(bootstrap_port).unwrap()
}

// NOTE For Fraser: This one is deprecated too, its funcitonality is now replaced by the
// BroadcastAcceptor
/// Listen for beacon broadcasts on port 5483 and reply with our_listening_address.
pub fn listen_for_broadcast(port: Option<Port>) -> Result<()> {
    let bootstrap_port: u16 = match port {
        Some(port) =>  { match port { Port::Tcp(num) => num }},
        None => 5483
    };

    println!("port is {:?}", bootstrap_port);

    let socket = try!( UdpSocket::bind(("0.0.0.0", bootstrap_port.clone())));

    let used_port:u16 = match socket.local_addr() {
                   Ok(sock_addr) => { sock_addr.port() },
                   Err(_) => panic!("should have port")
               };

    spawn(move || {
        loop {
            let mut buffer = [0; 4];
            match socket.recv_from(&mut buffer) {
                Ok((received_length, source)) => {
                    let bootstrap_contacts = || {
                        let handler = BootStrapHandler::new();
                        let contacts = handler.get_serialised_bootstrap_contacts();
                        contacts
                    };
                    let _ = socket.send_to(&bootstrap_contacts(), source);
                }
                Err(error) => println!("Failed receiving a message: {}", error)
            }
        }});

    Ok(())
}

// NOTE For Fraser: This is the test for the new API, I think the other one
// should be removed because:
// * It tests the old API (which I'm surprised passes givent that seek_peers
//   and listen_for_broadcast are no longer compatible)
// * It also tests the bootstrap.rs functionality but that doesn't seem to
//   be appropriate for this file.
#[test]
fn test_broadcast_second_version() {
    let acceptor = BroadcastAcceptor::bind(0).unwrap();
    let acceptor_port = acceptor.local_addr().unwrap().port();

    let t1 = thread::spawn(move || {
        let mut transport = acceptor.accept().unwrap();
        transport.sender.send(&"hello beacon".to_string().into_bytes()).unwrap();
    });

    let t2 = thread::spawn(move || {
        let endpoint = seek_peers_2(acceptor_port).unwrap()[0];
        let mut transport = transport::connect(transport::Endpoint::Tcp(endpoint)).unwrap();
        let msg = String::from_utf8(transport.receiver.receive().unwrap()).unwrap();
        assert!(msg == "hello beacon".to_string());
    });

    assert!(t1.join().is_ok());
    assert!(t2.join().is_ok());
}

#[cfg(test)]
mod test {
    use super::*;
    use std::net::{UdpSocket/*, lookup_addr, lookup_host*/};
    use std::thread;
    use transport::{Port, Endpoint};
    use bootstrap::{BootStrapHandler, BootStrapContacts, Contact, PublicKey};
    use sodiumoxide::crypto::asymmetricbox;

    #[test]
    fn test_broadcast() {
        let port = Port::Tcp(5493);
        // Start a normal socket and start listening for a broadcast
        let port2 = port.clone();
        thread::spawn(move || {
            let normal_socket = match UdpSocket::bind("::0:0") {
                Ok(s) => s,
                Err(e) => panic!("Couldn't bind socket: {}", e),
            };
            println!("Normal socket on {:?}\n", normal_socket.local_addr().unwrap());

            let endpoint = Endpoint::Tcp(normal_socket.local_addr().unwrap());
            let public_key = PublicKey::Asym(asymmetricbox::PublicKey([0u8; asymmetricbox::PUBLICKEYBYTES]));

            let mut contacts = BootStrapContacts::new();
            contacts.push(Contact::new(endpoint, public_key));

            let mut bootstrap_handler = BootStrapHandler::new();
            bootstrap_handler.add_bootstrap_contacts(contacts);

            let _ = listen_for_broadcast(Some(port2));
        });

        // Allow listener time to start
        thread::sleep_ms(300);

        for i in 0..3 {
            let peers = seek_peers(Some(port.clone()));
            assert!(peers.len() > 0);
        }
    }
}
