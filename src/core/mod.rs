#![allow(unused_imports, dead_code)]

pub mod asar;
pub mod detector;
pub mod opcodes;
pub mod patcher;
pub mod v8_cache;

pub use asar::read_asar_package_version;
pub use detector::{
    find_asar_in_path, find_installations, find_targets_in_path, get_quick_status,
    FoundTarget, SystemComponentsStatus, TargetKind,
};
pub use opcodes::*;
pub use patcher::{
    check_binary_state, invalidate_binary_cache, patch_target, restore_target, BinaryState,
};
pub use v8_cache::clear_ide_v8_caches;
