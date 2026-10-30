pub mod command;
pub mod env;
pub mod file_lock;
pub mod fs_utils;
mod guarded_io;
pub mod journal;
pub mod lock;
#[cfg(any(target_os = "macos", test))]
pub mod macos_shutdown;
#[cfg(windows)]
pub mod powershell;
pub mod privilege;
pub mod process;
pub mod service;
#[cfg(any(windows, unix, test))]
pub mod user_context;

pub use lock::check_single_instance;
pub use privilege::ensure_admin;
pub use service::FORWARDER_FLAG;
