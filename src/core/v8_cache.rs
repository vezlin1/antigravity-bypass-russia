use std::fs;
use std::path::PathBuf;
use crate::system::env::get_user_homes;

pub fn clear_ide_v8_caches() -> usize {
    let mut dirs_to_clear: Vec<PathBuf> = Vec::new();
    let homes = get_user_homes();

    for home in &homes {
        #[cfg(target_os = "windows")]
        {
            dirs_to_clear.push(
                home.join("AppData")
                    .join("Roaming")
                    .join("Antigravity IDE")
                    .join("CachedData"),
            );
            dirs_to_clear.push(
                home.join("AppData")
                    .join("Roaming")
                    .join("Antigravity IDE")
                    .join("Code Cache"),
            );
            dirs_to_clear.push(
                home.join("scoop")
                    .join("persist")
                    .join("antigravity-ide")
                    .join("data")
                    .join("user-data")
                    .join("CachedData"),
            );
            dirs_to_clear.push(
                home.join("scoop")
                    .join("persist")
                    .join("antigravity-ide")
                    .join("data")
                    .join("user-data")
                    .join("Code Cache"),
            );
        }
        #[cfg(target_os = "macos")]
        {
            let app_names = ["Antigravity", "Antigravity IDE", "Google Antigravity"];
            for name in app_names {
                dirs_to_clear.push(
                    home.join("Library")
                        .join("Application Support")
                        .join(name)
                        .join("CachedData"),
                );
                dirs_to_clear.push(
                    home.join("Library")
                        .join("Application Support")
                        .join(name)
                        .join("Code Cache"),
                );
            }
            dirs_to_clear.push(
                home.join("Library")
                    .join("Caches")
                    .join("com.google.antigravity")
                    .join("Cache"),
            );
            dirs_to_clear.push(
                home.join("Library")
                    .join("Caches")
                    .join("Antigravity"),
            );
            dirs_to_clear.push(
                home.join("Library")
                    .join("Caches")
                    .join("Antigravity IDE"),
            );
        }
        #[cfg(all(unix, not(target_os = "macos")))]
        {
            dirs_to_clear.push(
                home.join(".config")
                    .join("Antigravity IDE")
                    .join("CachedData"),
            );
            dirs_to_clear.push(
                home.join(".config")
                    .join("Antigravity IDE")
                    .join("Code Cache"),
            );
        }
    }

    dirs_to_clear.sort();
    dirs_to_clear.dedup();

    let mut cleared = 0;
    for dir in dirs_to_clear {
        if let Ok(entries) = fs::read_dir(&dir) {
            for entry in entries.flatten() {
                if let Ok(ft) = entry.file_type() {
                    let path = entry.path();
                    if ft.is_dir() {
                        if fs::remove_dir_all(&path).is_ok() {
                            cleared += 1;
                        }
                    } else if ft.is_file() && fs::remove_file(&path).is_ok() {
                        cleared += 1;
                    }
                }
            }
        }
    }
    cleared
}
