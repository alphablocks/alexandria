pub mod model;
pub mod portability;
pub mod private_fs;
pub mod rpc;
pub mod service;
pub mod store;
#[cfg(windows)]
pub use alexandria_windows as windows;

pub use model::{Error, Result};
pub use service::Service;
pub use store::Store;
