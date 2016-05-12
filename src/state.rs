use core::{Core, CoreTimeout};
use mio::{Token, EventLoop, EventSet};

pub trait State {
    fn execute(&mut self,
               _core: &mut Core,
               _event_loop: &mut EventLoop<Core>,
               _token: Token,
               _event_set: EventSet) {
    }
    fn timeout(&mut self,
               _core: &mut Core,
               _event_loop: &mut EventLoop<Core>,
               _timeout: CoreTimeout) {
    }
    fn write(&mut self, _core: &mut Core, _event_loop: &mut EventLoop<Core>, _data: Vec<u8>) {}
    fn terminate(&mut self, _core: &mut Core, _event_loop: &mut EventLoop<Core>) {}
}
