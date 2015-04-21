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
       simple_client -s
       simple_client -b <bootstrap>

Options:
    -h, --help          This message.
    -s, --start         startup a client.
    -b, --bootstrap     startup a client and bootstrap to the target.
";

#[derive(RustcDecodable, Debug)]
struct Args {
    arg_bootstrap: Option<String>,
    flag_start: bool,
    flag_bootstrap: bool,
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
        } else if args.flag_start {
            command = "start".to_string();
        } else if args.flag_bootstrap {
            command = "bootstrap".to_string();
            target = args.arg_bootstrap.unwrap();
        }
    }
    let mut keeps_going = true;
    while keeps_going {
        match command.trim() {
            "start" => {
                println!("start");
            }
            "bootstrap" => {
                println!("bootstraping");
            }
            "terminate" => {
                println!("terminating the client");
                keeps_going = false;
            }
            _ => println!("reading command :"),
        }
        command.clear();
        if keeps_going {
            let _ = io::stdin().read_line(&mut command);
        }
    }



    // // incoming: (u64, u64)
    // // outgoing: u64
    // let (i, mut o) = crust::tcp_connections::connect_tcp(std::net::SocketAddr::from_str("127.0.0.1:5483").unwrap()).unwrap();

    // // Send all the numbers from 0 to 10.
    // for x in (0u64..10u64) {
    //     o.send(&x).ok();
    // }

    // // Close our outgoing pipe. This is necessary because otherwise,
    // // the server will keep waiting for the client to send it data and
    // // we will deadlock.
    // o.close();

    // // Print everything that we get back.
    // for a in i.iter() {
    //     let (x, fx): (u64, u64) = a;
    //     println!("{} -> {}", x, fx);
    // }
}
