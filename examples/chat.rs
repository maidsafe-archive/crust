// Copyright 2017 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under (1) the MaidSafe.net Commercial License,
// version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
// licence you accepted on initial access to the Software (the "Licences").
//
// By contributing code to the SAFE Network Software, or to this project generally, you agree to be
// bound by the terms of the MaidSafe Contributor Agreement.  This, along with the Licenses can be
// found in the root directory of this project at LICENSE, COPYING and CONTRIBUTOR.
//
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.
//
// Please review the Licences for the specific language governing permissions and limitations
// relating to use of the SAFE Network Software.

//! This example demonstrates how to make a rendezvous connection using `crust`.
//!
//! In order to make a connection we need to:
//!
//! 1. create a `Service` object.
//! 2. call `prepare_connection_info` to obtain a `PrivConnectionInfo`
//! 3. create a `PubConnectionInfo` from our `PrivConnectionInfo`
//! 4. exchange `PubConnectionInfo` objects with the peer we are connecting to.
//! 5. call `connect` using the peer's `PubConnectionInfo` and our `PrivConnectionInfo`
//!
//! Run two instances of this sample: preferably on separate computers but
//! localhost is fine too.
//! When the sample starts it prints generated public information which
//! is represented as JSON object.
//! Copy this object from first to second peer and hit ENTER.
//! Do the same with the second peer: copy it's public information JSON
//! to first peer and hit ENTER.
//! On both peers you should see something like:
//! ```
//! You are now connected! say hello :)
//! ```
//! That's it, it means we successfully did a peer-to-peer connection. You can now use this
//! connection to chat to the remote peer.

extern crate chrono;
extern crate clap;
extern crate env_logger;
extern crate future_utils;
extern crate futures;
extern crate maidsafe_utilities;
extern crate rand;
extern crate serde;
#[macro_use]
extern crate serde_derive;
extern crate serde_json;
extern crate tokio_core;
#[macro_use]
extern crate unwrap;
extern crate bytes;
extern crate safe_crypto;
extern crate void;

extern crate crust;

mod utils;

use bytes::Bytes;
use chrono::Local;
use clap::{App, Arg};
use crust::config::{DevConfigSettings, PeerInfo};
use crust::{ConfigFile, Listener, PaAddr, Peer, PubConnectionInfo, Service, MAX_PAYLOAD_SIZE};
use future_utils::{bi_channel, thread_future, BoxFuture, FutureExt};
use futures::future::Either;
use futures::sync::mpsc::{self, UnboundedReceiver, UnboundedSender};
use futures::{Async, Future, Sink, Stream};
use maidsafe_utilities::serialisation::{deserialise, serialise};
use safe_crypto::SecretId;
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::Path;
use std::process;
use std::str::FromStr;
use tokio_core::reactor::{Core, Handle};
use utils::read_line;
use void::Void;

/// Leave some room for our metadata.
const FILE_CHUNK_SIZE: usize = MAX_PAYLOAD_SIZE - 1024;

/// Prints current time and given formatted string.
macro_rules! out {
    ($($arg:tt)*) => ({
        let date = Local::now();
        print!("\r{} ", date.format("%H:%M"));
        println!($($arg)*);
    });
}

#[derive(Debug)]
struct Args {
    rendezvous_peer: Option<PeerInfo>,
    disable_tcp: bool,
    disable_igd: bool,
    disable_direct_connections: bool,
}

/// Message type that will be exchange between peers.
#[derive(Debug, Serialize, Deserialize)]
enum Message {
    Text(String),
    FileRequest(String),
    FileAccept(String),
    FileReject(String),
    FileChunk(String, Vec<u8>),
    FileAllSent(String),
}

#[derive(Debug, Clone)]
enum InputState {
    /// Usual state when ordinary text is being typed.
    Text,
    /// Waiting for y/n confirmation.
    WaitingToConfirmFile(String),
    SendingFile(String),
}

fn main() {
    unwrap!(env_logger::init());
    let args = match parse_cli_args() {
        Ok(args) => args,
        Err(e) => e.exit(),
    };
    let mut core = unwrap!(Core::new());
    let handle = core.handle();

    print_logo();

    let future = Node::run(&handle, args)
        .and_then(|node| node.connect())
        .and_then(|(node, peer)| node.have_a_conversation_with(peer));
    match core.run(future) {
        Ok(()) => (),
        Err(v) => void::unreachable(v),
    }
}

/// Chat node/peer
struct Node {
    service: Service,
    #[allow(unused)]
    listeners: Vec<Listener>,
    handle: Handle,
}

impl Node {
    /// Constructs Crust `Service` and starts listeners.
    fn run(handle: &Handle, args: Args) -> BoxFuture<Self, Void> {
        let config = args.make_config();
        let our_sk = SecretId::new();
        let handle = handle.clone();
        Service::with_config(&handle, config, our_sk, Vec::new())
            .map_err(|e| panic!("error starting service: {}", e))
            .map(move |service| {
                if args.disable_igd {
                    service.p2p_config().disable_igd();
                }
                service
            })
            .and_then(|service| {
                out!("Our ID: {:?}", service.id());
                service
                    .start_listening()
                    .map_err(|e| panic!("Failed to start listeners: {}", e))
                    .collect()
                    .map(move |listeners| Self {
                        service,
                        listeners,
                        handle,
                    })
            })
            .into_boxed()
    }

    /// Get peer info from stdin and attempt to connect to it.
    fn connect(self) -> BoxFuture<(Node, Peer), Void> {
        let (ci_channel1, ci_channel2) = bi_channel::unbounded();
        let exchange_ci = ci_channel2
            .into_future()
            .and_then(|(our_ci_opt, ci_channel2)| {
                let our_ci = unwrap!(our_ci_opt);
                let as_str = unwrap!(serde_json::to_string(&our_ci));
                out!("Our connection info:");
                println!("{}", as_str);
                println!();
                out!(
                    "Copy this info and share it with your connecting partner. Then paste \
                     their info below."
                );
                read_line().infallible().and_then(move |ln| {
                    let their_info: PubConnectionInfo = unwrap!(serde_json::from_str(&ln));
                    unwrap!(ci_channel2.unbounded_send(their_info));
                    Ok(())
                })
            })
            .then(|_| Ok(()));
        self.handle.spawn(exchange_ci);

        self.service
            .connect(ci_channel1)
            .map_err(|e| panic!("error connecting to peer: {}", e))
            .map(move |peer| (self, peer))
            .into_boxed()
    }

    fn have_a_conversation_with(self, peer: Peer) -> BoxFuture<(), Void> {
        out!(
            "You are now connected to '{}'! Say hello :) Or type /help to see possible commands.",
            unwrap!(peer.addr())
        );

        let peer_display_name0 = peer.uid().clone();
        let peer_display_name1 = peer.uid().clone();
        let (peer_sink, peer_stream) = peer.split();
        let (input_handler, input_state_tx) = InputHandler::new();

        let writer = peer_sink
            .sink_map_err(|e| panic!("error sending message to peer: {}", e))
            .send_all(input_handler.map(|msg| Bytes::from(unwrap!(serialise(&msg)))));
        let reader = peer_stream
            .map_err(|e| panic!("error receiving message from peer: {}", e))
            .for_each(move |msg| {
                handle_peer_msg(&msg, &input_state_tx, &format!("{:?}", peer_display_name0));
                Ok(())
            })
            .map(move |()| {
                out!("Peer <{:?}> disconnected", peer_display_name1);
            });

        writer
            .select2(reader)
            .map(move |either| match either {
                Either::A((_, _next)) => (),
                Either::B(((), _next)) => drop(self.service),
            })
            .map_err(|either| match either {
                Either::A((v, _next)) => v,
                Either::B((v, _next)) => v,
            })
            .into_boxed()
    }
}

/// Asynchronous file read result. On EOF, None is expected.
type FileContentResult = Option<(Vec<u8>, File)>;

/// Our input handler: reads commands from stdin, reacts accordingly and emits messages to
/// be sent to connected peer.
struct InputHandler {
    input_state_rx: UnboundedReceiver<InputState>,
    input_state: InputState,
    fut_read_ln: BoxFuture<String, Void>,
    read_file_fut: Option<BoxFuture<FileContentResult, Void>>,
}

impl InputHandler {
    /// Returns new input handler and input state sender.
    fn new() -> (Self, UnboundedSender<InputState>) {
        print!("\r> ");
        unwrap!(io::stdout().flush());
        let (input_state_tx, input_state_rx) = mpsc::unbounded();
        let input_handler = Self {
            input_state_rx,
            input_state: InputState::Text,
            fut_read_ln: read_line(),
            read_file_fut: None,
        };
        (input_handler, input_state_tx)
    }

    /// Handles command that the user inputs.
    /// Returns message that will be sent to connected peer, if applicable to given command.
    fn handle_input(&mut self, line: &str) -> Option<Message> {
        let cmd = line.trim_right().to_owned();
        if cmd.starts_with("/send") {
            Some(Message::FileRequest(cmd[6..].to_owned()))
        } else if cmd.starts_with("/exit") {
            process::exit(0)
        } else if cmd.starts_with("/help") {
            println!("Possible commands:");
            println!("  /help - prints this help menu");
            println!("  /exit - terminates chat app");
            println!(
                "  /send $file_path - attempts to send given file to connected peer. File path \
                 might be relative or absolute."
            );
            print!("\r> ");
            unwrap!(io::stdout().flush());
            None
        } else {
            let msg = match self.input_state {
                InputState::WaitingToConfirmFile(ref fname) => {
                    if &cmd[..] == "y" {
                        truncate_file(&file_name(fname));
                        Message::FileAccept(fname.clone())
                    } else {
                        Message::FileReject(fname.clone())
                    }
                }
                _ => Message::Text(cmd),
            };
            self.input_state = InputState::Text;
            Some(msg)
        }
    }

    /// Opens file to be sent out.
    fn open_file(&mut self, fname: &str) {
        let file = unwrap!(OpenOptions::new().read(true).open(fname));
        self.read_file_fut = Some(async_read_file(file));
    }

    /// If we're in `SendingFile` state, let's read file chunk from disk.
    /// None is returned, when EOF is reached.
    fn poll_file_chunk(&mut self) -> Result<Async<Option<Vec<u8>>>, Void> {
        if let Some(mut read_file_fut) = self.read_file_fut.take() {
            let ret = match read_file_fut.poll() {
                Ok(Async::Ready(Some((chunk, file)))) => {
                    self.read_file_fut = Some(async_read_file(file));
                    return Ok(Async::Ready(Some(chunk)));
                }
                Ok(Async::Ready(None)) => Async::Ready(None),
                _ => Async::NotReady,
            };
            self.read_file_fut = Some(read_file_fut);
            return Ok(ret);
        }
        Ok(Async::NotReady)
    }

    /// See if we should change input state.
    fn check_state_change(&mut self) {
        if let Ok(Async::Ready(Some(state))) = self.input_state_rx.poll() {
            if let InputState::SendingFile(ref fname) = state {
                self.open_file(fname);
            }
            self.input_state = state;
        }
    }

    /// Updates read line future.
    fn read_ln_from_stdin(&mut self) {
        print!("\r> ");
        unwrap!(io::stdout().flush());
        self.fut_read_ln = read_line();
    }
}

impl Stream for InputHandler {
    type Item = Message;
    type Error = Void;

    /// Yields messages to send to connected peer.
    fn poll(&mut self) -> Result<Async<Option<Self::Item>>, Self::Error> {
        self.check_state_change();
        if let InputState::SendingFile(fname) = self.input_state.clone() {
            if let Ok(Async::Ready(chunk)) = self.poll_file_chunk() {
                let msg = match chunk {
                    Some(content) => Message::FileChunk(fname, content),
                    None => {
                        self.input_state = InputState::Text;
                        out!("Finished sending file: {}", fname);
                        Message::FileAllSent(fname)
                    }
                };
                return Ok(Async::Ready(Some(msg)));
            }
        }

        match self.fut_read_ln.poll() {
            Ok(Async::Ready(line)) => {
                self.read_ln_from_stdin();
                let msg_to_send = self.handle_input(&line);
                Ok(msg_to_send
                    .map(|msg| Async::Ready(Some(msg)))
                    .unwrap_or(Async::NotReady))
            }
            Ok(Async::NotReady) => Ok(Async::NotReady),
            Err(e) => Err(e),
        }
    }
}

/// Handles message received from connected peer.
fn handle_peer_msg(
    msg: &[u8],
    input_state_tx: &UnboundedSender<InputState>,
    peer_display_name: &str,
) {
    let msg = unwrap!(deserialise(msg));
    match msg {
        Message::Text(line) => {
            out!("<{}> {}", peer_display_name, line);
        }
        Message::FileRequest(fname) => {
            out!(
                "<{}> is trying to send you file '{}'. Accept? y/n?",
                peer_display_name,
                fname
            );
            let _ = input_state_tx.unbounded_send(InputState::WaitingToConfirmFile(fname));
        }
        Message::FileAccept(fname) => {
            out!("Request to send '{}'  was accepted, sending...", fname);
            let _ = input_state_tx.unbounded_send(InputState::SendingFile(fname));
        }
        Message::FileReject(fname) => out!("Request to send '{}'  was rejected!", fname),
        Message::FileChunk(fname, content) => {
            append_to_file(&file_name(&fname), &content);
        }
        Message::FileAllSent(fname) => out!("'{}'  was successfully received.", file_name(&fname)),
    };
    print!("\r> ");
    unwrap!(io::stdout().flush());
}

fn parse_cli_args() -> Result<Args, clap::Error> {
    let matches = App::new("Simple chat app built on Crust")
        .about(
            "This chat app connects two machines directly without intermediate servers and allows \
             to exchange messages securely. All the messages are end to end encrypted.",
        )
        .arg(
            Arg::with_name("rendezvous-peer")
                .long("rendezvous-peer")
                .value_name("ADDR")
                .help("Address of peer to use as a rendezvous server.")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("rendezvous-peer-key")
                .long("rendezvous-peer-key")
                .value_name("KEY")
                .help("Rendezvous peer public key.")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("disable-tcp")
                .long("disable-tcp")
                .help("Connect using uTP only.")
                .takes_value(false),
        )
        .arg(
            Arg::with_name("disable-igd")
                .long("disable-igd")
                .help("Disable IGD/UPnP.")
                .takes_value(false),
        )
        .arg(
            Arg::with_name("disable-direct-connections")
                .long("disable-direct-connections")
                .help(
                    "By default chat will try to connect to the peer in all possible methods: \
                     directly or via hole punching. This flag disables direct connections leaving \
                     only rendezvous connections to try.",
                )
                .takes_value(false),
        )
        .get_matches();

    let rendezvous_peer = match matches.value_of("rendezvous-peer") {
        Some(addr) => {
            let peer_addr = unwrap!(PaAddr::from_str(addr));
            let peer_key = matches
                .value_of("rendezvous-peer-key")
                .map(|key| unwrap!(serde_json::from_str(key)))
                .ok_or_else(|| {
                    clap::Error::with_description(
                        "If rendezvous peer address is given, public key must be present too.",
                        clap::ErrorKind::EmptyValue,
                    )
                })?;
            Some(PeerInfo::new(peer_addr, peer_key))
        }
        None => None,
    };
    Ok(Args {
        rendezvous_peer,
        disable_tcp: matches.occurrences_of("disable-tcp") > 0,
        disable_igd: matches.occurrences_of("disable-igd") > 0,
        disable_direct_connections: matches.occurrences_of("disable-direct-connections") > 0,
    })
}

impl Args {
    /// Constructs `Crust` config from CLI arguments.
    fn make_config(&self) -> ConfigFile {
        let config = unwrap!(ConfigFile::new_temporary());

        if let Some(ref peer_info) = self.rendezvous_peer {
            unwrap!(config.write()).hard_coded_contacts = vec![peer_info.clone()];
        }
        if self.disable_tcp {
            unwrap!(config.write()).dev = Some(DevConfigSettings {
                disable_tcp: true,
                ..Default::default()
            });
        }
        if !self.disable_direct_connections {
            unwrap!(config.write()).listen_addresses = vec![
                unwrap!("utp://0.0.0.0:0".parse()),
                unwrap!("tcp://0.0.0.0:0".parse()),
            ];
        }

        config
    }
}

fn print_logo() {
    println!(
        r#"
   _____                _      _____ _           _
  / ____|              | |    / ____| |         | |
 | |     _ __ _   _ ___| |_  | |    | |__   __ _| |_
 | |    | '__| | | / __| __| | |    | '_ \ / _` | __|
 | |____| |  | |_| \__ \ |_  | |____| | | | (_| | |_
  \_____|_|   \__,_|___/\__|  \_____|_| |_|\__,_|\__|

  "#
    );
}

fn append_to_file(fname: &str, content: &[u8]) {
    let mut file = unwrap!(OpenOptions::new().create(true).append(true).open(fname));
    unwrap!(file.write(content));
}

fn truncate_file(fname: &str) {
    let _ = unwrap!(
        OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(fname)
    );
}

/// Since we support cross-platforms, it would be best, if we stick to UTF-8 for filenames.
fn file_name(path: &str) -> String {
    unwrap!(
        Path::new(path)
            .file_name()
            .map(|s| unwrap!(s.to_str()).to_owned())
    )
}

/// Reads file in a separate thread, hence doesn't block current thread.
/// On EOF, returns None and file get's closed.
fn async_read_file(mut file: File) -> BoxFuture<FileContentResult, Void> {
    thread_future(move || {
        let mut buf = Vec::with_capacity(FILE_CHUNK_SIZE);
        unsafe { buf.set_len(FILE_CHUNK_SIZE) };

        let bytes_read = unwrap!(file.read(&mut buf));
        if bytes_read > 0 {
            unsafe { buf.set_len(bytes_read) };
            Some((buf, file))
        } else {
            None
        }
    }).into_boxed()
}
