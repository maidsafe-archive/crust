
use std::cmp::Ordering;
use std::ops::Deref;
use rustc_serialize::{Encodable, Decodable, Decoder, Encoder};

#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]     
pub struct SocketAddr(pub ::std::net::SocketAddr);       
      
impl Deref for SocketAddr {
    type Target = ::std::net::SocketAddr;

    fn deref(&self) -> &::std::net::SocketAddr {
        &self.0
    }
}

impl Encodable for SocketAddr {      
    fn encode<S: Encoder>(&self, s: &mut S) -> Result<(), S::Error> {     
        let as_string = format!("{}", self.0);        
        try!(s.emit_str(&as_string[..]));     
        Ok(())        
    }     
}     
      
impl Decodable for SocketAddr {      
    fn decode<D: Decoder>(d: &mut D) -> Result<SocketAddr, D::Error> {       
        let as_string = try!(d.read_str());       
        match ::std::net::SocketAddr::from_str(&as_string[..]) {      
            Ok(sa) => Ok(SocketAddr(sa)),        
            Err(e) => {       
                let err = format!("Failed to decode SocketAddr: {}", e);     
                Err(d.error(&err[..]))        
            }     
        }     
    }     
}     
      
/// Utility struct of SocketAddrV4 for hole punching      
#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]        
pub struct SocketAddrV4(pub ::std::net::SocketAddrV4);       
      
impl Encodable for SocketAddrV4 {        
    fn encode<S: Encoder>(&self, s: &mut S) -> Result<(), S::Error> {     
        unimplemented!()
    }
}     
      
impl Decodable for SocketAddrV4 {        
    fn decode<D: Decoder>(d: &mut D) -> Result<SocketAddrV4, D::Error> {     
        unimplemented!()
    }     
}     

