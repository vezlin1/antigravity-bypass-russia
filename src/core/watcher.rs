//! Automatic Background Update Watcher & JIT Repatcher.
//!
//! Monitors Antigravity IDE, CLI, and extension directories. When Google Antigravity
//! updates in the background and restores stock (unpatched) binaries or JS, the watcher
//! automatically reapplies patches and flushes V8 caches within milliseconds.

use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;

use crate::core::detector::{find_installations, find_targets_in_path};
use crate::core::patcher::{check_binary_state, patch_target, BinaryState};
use crate::core::v8_cache::clear_ide_v8_caches;

static WATCHER_RUNNING: AtomicBool = AtomicBool::new(false);

#[allow(dead_code)]
pub fn is_watcher_running() -> bool {
    WATCHER_RUNNING.load(Ordering::Relaxed)
}

/// Runs one inspection pass across all installed Antigravity targets.
/// Returns the number of targets that were detected as stock and repatched.
pub fn scan_and_repatch() -> usize {
    let mut repatched_count = 0;
    let installs = find_installations();

    for inst in installs {
        let targets = find_targets_in_path(&inst);
        for target in targets {
            let state = check_binary_state(&target.path);
            if state == BinaryState::Stock {
                println!(
                    "\x1b[93m[UpdateWatcher]\x1b[0m Обнаружена обновленная stock-версия: {}",
                    target.path.display()
                );
                let res = patch_target(&target);
                if res.is_ok() {
                    repatched_count += 1;
                    println!(
                        "\x1b[92m[UpdateWatcher]\x1b[0m Успешно пропатчен: {}",
                        target.name
                    );
                }
            }
        }
    }

    if repatched_count > 0 {
        clear_ide_v8_caches();
        println!(
            "\x1b[92m[UpdateWatcher]\x1b[0m Автоматически перепатчено {} файлов. Кэш V8 сброшен.",
            repatched_count
        );
    }

    repatched_count
}

/// Spawns the background watcher daemon thread.
pub fn spawn_watcher_thread(interval: Duration) {
    if WATCHER_RUNNING.swap(true, Ordering::SeqCst) {
        return; // Already running
    }

    thread::spawn(move || {
        loop {
            if !WATCHER_RUNNING.load(Ordering::Relaxed) {
                break;
            }
            let _ = scan_and_repatch();
            thread::sleep(interval);
        }
    });
}

/// Runs the watcher daemon in the foreground (for CLI `watch` subcommand).
pub fn run_watcher_loop(interval: Duration) {
    WATCHER_RUNNING.store(true, Ordering::SeqCst);
    println!("\x1b[96m[UpdateWatcher]\x1b[0m Фоновый мониторинг обновлений Antigravity запущен.");
    println!("\x1b[90m[UpdateWatcher] Интервал проверки: {:?}. Нажмите Ctrl+C для выхода.\x1b[0m\n", interval);

    // Initial check on start
    let _ = scan_and_repatch();

    loop {
        thread::sleep(interval);
        let _ = scan_and_repatch();
    }
}

#[allow(dead_code)]
pub fn stop_watcher() {
    WATCHER_RUNNING.store(false, Ordering::SeqCst);
}
