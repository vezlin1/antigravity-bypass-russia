pub mod asar;
pub mod detector;
pub mod endpoint;
mod endpoint_env;
#[cfg(any(target_os = "macos", test))]
mod endpoint_macos;
#[cfg(target_os = "macos")]
pub mod endpoint_session;
pub mod install_paths;
pub mod opcodes;
pub mod patcher;
pub mod v8_cache;
#[cfg(windows)]
mod windows_installations;
