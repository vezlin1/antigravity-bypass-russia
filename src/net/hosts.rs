#![allow(dead_code)]

use std::fs;
use std::io::Write;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};

const START_MARK: &str = "# BEGIN ANTIGRAVITY-BYPASS-RUSSIA";
const END_MARK: &str = "# END ANTIGRAVITY-BYPASS-RUSSIA";

pub fn hosts_path() -> PathBuf {
    #[cfg(target_os = "windows")]
    {
        let root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".to_string());
        PathBuf::from(root).join("System32").join("drivers").join("etc").join("hosts")
    }
    #[cfg(not(target_os = "windows"))]
    {
        PathBuf::from("/etc/hosts")
    }
}

pub fn write_entries(entries: &[(String, Ipv4Addr)]) -> Result<(), String> {
    let p = hosts_path();
    let original = if p.exists() {
        fs::read_to_string(&p).map_err(|e| format!("Чтение hosts: {}", e))?
    } else {
        String::new()
    };

    let stripped = strip_block(&original);
    let mut block = String::new();
    block.push_str(START_MARK);
    block.push('\n');
    for (host, ip) in entries {
        block.push_str(&format!("{} {}\n", ip, host));
    }
    block.push_str(END_MARK);
    block.push('\n');

    let combined = if stripped.trim().is_empty() {
        block
    } else {
        format!("{}\n\n{}", stripped.trim_end(), block)
    };

    safe_write_hosts(&p, combined.as_bytes())
}

pub fn remove_entries() -> Result<(), String> {
    let p = hosts_path();
    if !p.exists() {
        return Ok(());
    }
    let original = fs::read_to_string(&p).map_err(|e| format!("Чтение hosts: {}", e))?;
    let stripped = strip_block(&original);
    if stripped != original {
        safe_write_hosts(&p, stripped.as_bytes())?;
    }
    Ok(())
}

fn strip_block(text: &str) -> String {
    let mut result = Vec::new();
    let mut in_block = false;
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed == START_MARK {
            in_block = true;
            continue;
        }
        if trimmed == END_MARK {
            in_block = false;
            continue;
        }
        if !in_block {
            result.push(line);
        }
    }
    result.join("\n")
}

fn safe_write_hosts(path: &Path, data: &[u8]) -> Result<(), String> {
    if let Ok(meta) = fs::metadata(path) {
        let mut perms = meta.permissions();
        if perms.readonly() {
            #[allow(clippy::permissions_set_readonly_false)]
            perms.set_readonly(false);
            let _ = fs::set_permissions(path, perms);
        }
    }

    let mut file = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(path)
        .map_err(|e| format!("Открытие hosts: {}", e))?;

    file.write_all(data).map_err(|e| format!("Запись hosts: {}", e))?;
    file.flush().map_err(|e| format!("Flush hosts: {}", e))?;
    Ok(())
}
