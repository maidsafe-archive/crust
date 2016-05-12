use std::sync::mpsc::Sender;
use std::net::SocketAddr;
use std::collections::HashMap;

use state::State;
use std::sync::{Arc, Mutex};
use core::{Core, CoreMessage, Context};
use mio::{self, EventLoop};
use connection_states::EstablishConnection;
use maidsafe_utilities::thread::RaiiThreadJoiner;

pub enum CrustMsg {
    NewConnection(u64),
    NewMessage(u64, Vec<u8>),
}

pub struct Service {
    tx: Sender<CrustMsg>,
    context_counter: usize,
    mio_tx: mio::Sender<CoreMessage>,
    cm: Arc<Mutex<HashMap<u64, Context>>>,
    _raii_joiner: RaiiThreadJoiner,
}

impl Service {
    pub fn new(tx: Sender<CrustMsg>) -> Self {
        let event_loop = EventLoop::new().expect("Unable to create event loop");
        let mio_tx = event_loop.channel();

        let raii_joiner = RaiiThreadJoiner::new(thread!("CoreEventLoop", move || {
            let mut core = Core::new();
            event_loop.run(&mut core).expect("EventLoop failed to run");
        }));

        Service {
            tx: tx,
            context_counter: 0,
            mio_tx: mio_tx,
            cm: Arc::new(Mutex::new(HashMap::new())),
            _raii_joiner: raii_joiner,
        }
    }

    pub fn connect(&mut self, peer_contact_info: SocketAddr) {
        let routing_tx = self.tx.clone();
        let cm = self.cm.clone();

        let _ = self.mio_tx
                    .send(Box::new(move |core: &mut Core, event_loop: &mut EventLoop<Core>| {
                        EstablishConnection::new(core,
                                                 event_loop,
                                                 cm,
                                                 routing_tx,
                                                 peer_contact_info);
                    }));
    }

    pub fn drop_peer(&mut self, peer_id: u64) {
        let context = self.cm.lock().unwrap().remove(&peer_id).expect("Context not found");
        let _ = self.mio_tx.send(Box::new(move |core, event_loop| {
            let state = core.get_state(&context).expect("State not found").clone();
            state.borrow_mut().terminate(&mut core, &mut event_loop);
        }));
    }

    pub fn send(&mut self, peer_id: u64, data: Vec<u8>) {
        let context = self.cm.lock().unwrap().get(&peer_id).expect("Context not found").clone();
        let _ = self.mio_tx.send(Box::new(move |core, event_loop| {
            let state = core.get_state(&context).expect("State not found").clone();
            state.borrow_mut().write(&mut core, &mut event_loop, data);
        }));
    }
}

impl Drop for Service {
    fn drop(&mut self) {
        let _ = self.mio_tx.send(Box::new(|_, el| el.shutdown()));
    }
}
