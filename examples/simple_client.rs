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

extern crate docopt;
extern crate rustc_serialize;

extern crate crust;

use docopt::Docopt;

use std::str::FromStr;
use std::io;
use std::env;

// simple_client -e filename
// basic_encryptor -d datamap destination
// basic_encryptor -h | --help
static USAGE: &'static str = "
Usage: simple_client -h
       simple_client -c <peer>

Options:
    -h, --help          This message.
    -c, --connect       startup a client and connect to the peer.
";

#[derive(RustcDecodable, Debug)]
struct Args {
    arg_peer: Option<String>,
    flag_connect: bool,
    flag_help: bool,
}

fn main() {
    let mut command = String::new();
    let mut target = String::new();
    let parsed = Docopt::new(USAGE).and_then(|d| d.decode() );
    if parsed.is_ok() {
        let args: Args = parsed.unwrap();
        if args.flag_help {
            println!("{:?}", args);
        } else if args.flag_connect {
            command = "connect".to_string();
            target = args.arg_peer.unwrap();
        }
    }

    let (i, mut o) = crust::tcp_connections::connect_tcp(std::net::SocketAddr::from_str(target.trim()).unwrap()).unwrap();

    let mut keeps_going = true;
    while keeps_going {
        match command.trim() {
            "send" => {
                println!("reading the msg to be sent : ");
                let mut msg = String::new();
                let _ = io::stdin().read_line(&mut msg);
                o.send(&msg).ok();
            }
            _ => println!("reading command :"),
        }
        command.clear();
        if keeps_going {
            let _ = io::stdin().read_line(&mut command);
        }
    }
    o.close();

}
