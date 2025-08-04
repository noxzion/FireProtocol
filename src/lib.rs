pub mod crypto;
pub mod protocol;
pub mod network;
pub mod session;
pub mod utils;
pub mod error;
pub mod key_exchange;

#[no_mangle]
pub extern "C" fn fire_protocol_version() -> *const u8 {
    b"0.1.0\0".as_ptr()
}

pub use crypto::*;
pub use protocol::*;
pub use network::*;
pub use session::*;
pub use utils::*;
pub use key_exchange::*; 