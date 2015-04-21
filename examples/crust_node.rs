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

extern crate crust;
extern crate rand;

use transport::{Endpoint, Port};

// simple "NodeInfo", without PKI
struct CrustNode {
  pub endpoint : Endpoint,
  pub connected : bool
}

impl CrustNode {
  pub fn new(endpoint : Endpoint) -> CrustNode {
    CrustNode{
      endpoint : endpoint,
      connected : false
    }
  }
  pub fn set_connected(&mut self) {self.connected = true;}
  pub fn set_disconnected(&mut self) {self.connected = false;}
}

struct FlatWorld {
  our_ep : Endpoint,
  crust_nodes : Vec<CrustNode>
}

// simple "routing table" without any structure
impl FlatWorld {
  pub fn new(our_endpoint : Endpoint) -> FlatWorld {
    FlatWorld {
      our_ep : our_endpoint,
      crust_nodes : Vec::with_capacity(40)
    }
  }

  // Will add node if not duplicated.  Returns true when added.
  pub fn add(new_endpoint : Endpoint) -> bool {
    
  }
}

fn main() {
  let (cm_tx, cm_rx = channel();
  let cm = ConnectionManager::new(cm_tx);
  let cm_eps = match cm.start_listening(vec![Port::Tcp(0)]) {
    Ok(eps) => eps,
    Err(e) => panic!("Connection manager failed to start on arbitrary TCP port: {}", e)
  };

  if false { // beacon nor stored_bootstrap_endpoints
    cm.
  }
}
