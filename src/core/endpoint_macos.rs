//! macOS: point Antigravity App and CLI at the daily endpoint.
//!
//! The App reads `CLOUD_CODE_URL` from the GUI session (`launchctl setenv`);
//! a LaunchAgent repeats it at every login. The CLI reads it from a marked
//! block in the shell profiles. Rollback removes only what was added here and
//! keeps values that the user set or changed.

const DAILY: &str = super::endpoint::DAILY_ENDPOINT;
const AGENT_LABEL: &str = "com.antigravity.bypass.daily-endpoint";
const BEGIN: &str = "# >>> antigravity-bypass-russia: CLOUD_CODE_URL >>>";
const END: &str = "# <<< antigravity-bypass-russia: CLOUD_CODE_URL <<<";

fn block() -> String {
    format!("{BEGIN}\nexport CLOUD_CODE_URL=\"{DAILY}\"\n{END}\n")
}

/// Profile text with our block added or refreshed. `None` when the profile
/// mentions `CLOUD_CODE_URL` on its own: the user's value is kept.
fn with_block(text: &str) -> Option<String> {
    let mut out = without_block(text);
    if out.contains("CLOUD_CODE_URL") {
        return None;
    }
    if !out.is_empty() && !out.ends_with('\n') {
        out.push('\n');
    }
    out.push_str(&block());
    Some(out)
}

/// Profile text without our complete blocks. An unterminated block is kept.
fn without_block(text: &str) -> String {
    let mut out = String::new();
    let mut rest = text;
    while let Some(start) = rest.find(BEGIN) {
        let Some(length) = rest[start..].find(END) else {
            break;
        };
        out.push_str(&rest[..start]);
        let mut after = start + length + END.len();
        if rest[after..].starts_with("\r\n") {
            after += 2;
        } else if rest[after..].starts_with('\n') {
            after += 1;
        }
        rest = &rest[after..];
    }
    out.push_str(rest);
    out
}

fn agent_plist() -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>{AGENT_LABEL}</string>
  <key>ProgramArguments</key>
  <array>
    <string>/bin/launchctl</string>
    <string>setenv</string>
    <string>CLOUD_CODE_URL</string>
    <string>{DAILY}</string>
  </array>
  <key>RunAtLoad</key>
  <true/>
</dict>
</plist>
"#
    )
}

#[cfg(target_os = "macos")]
pub use platform::{apply_if_default, cli_configured, restore};

#[cfg(target_os = "macos")]
mod platform {
    use super::{agent_plist, with_block, without_block, AGENT_LABEL, DAILY};
    use crate::core::endpoint_session as session;
    use crate::system::env::expand_env_vars;
    use crate::system::fs_utils::{create_private_directory, robust_write_file};
    use serde::{Deserialize, Serialize};
    use std::fs;
    use std::io::ErrorKind;
    use std::path::PathBuf;

    #[derive(Serialize, Deserialize)]
    struct Profile {
        path: PathBuf,
        created: bool,
    }

    #[derive(Default, Serialize, Deserialize)]
    struct State {
        /// The GUI session value before the change, when this tool set it.
        session_original: Option<Option<String>>,
        agent: bool,
        profiles: Vec<Profile>,
    }

    fn state_path() -> PathBuf {
        crate::net::config::directory().join("macos-daily-endpoint.json")
    }

    fn load() -> Result<Option<State>, String> {
        match fs::read(state_path()) {
            Ok(bytes) => serde_json::from_slice(&bytes)
                .map(Some)
                .map_err(|_| "Повреждена копия настроек endpoint macOS".into()),
            Err(error) if error.kind() == ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error.to_string()),
        }
    }

    fn save(state: &State) -> Result<(), String> {
        fs::create_dir_all(crate::net::config::directory()).map_err(|e| e.to_string())?;
        robust_write_file(
            &state_path(),
            &serde_json::to_vec(state).map_err(|e| e.to_string())?,
        )
    }

    fn agent_path() -> PathBuf {
        expand_env_vars("~/Library/LaunchAgents").join(format!("{AGENT_LABEL}.plist"))
    }

    /// `~/.zshenv` is read by every zsh, the default macOS shell. Bash reads
    /// `~/.bash_profile` in Terminal; it is changed only if it already exists.
    fn profiles() -> [(PathBuf, bool); 2] {
        [
            (expand_env_vars("~/.zshenv"), true),
            (expand_env_vars("~/.bash_profile"), false),
        ]
    }

    fn read_profile(path: &std::path::Path) -> Result<Option<String>, String> {
        match fs::read_to_string(path) {
            Ok(text) => Ok(Some(text)),
            Err(error) if error.kind() == ErrorKind::NotFound => Ok(None),
            Err(error) => Err(format!("{}: {error}", path.display())),
        }
    }

    pub fn apply_if_default() -> Result<String, String> {
        let mut state = load()?.unwrap_or_default();
        let mut notes = Vec::new();

        let current = session::read()?;
        let custom = current
            .as_deref()
            .is_some_and(|value| !super::super::endpoint_env::managed_endpoint(value));
        if custom {
            notes.push("App: собственный CLOUD_CODE_URL сессии сохранён".to_string());
        } else {
            if current.as_deref() != Some(DAILY) && state.session_original.is_none() {
                state.session_original = Some(current);
                save(&state)?;
            }
            if state.session_original.is_some() {
                session::write(Some(DAILY))?;
                let path = agent_path();
                let plist = agent_plist();
                match read_profile(&path)? {
                    Some(existing) if existing == plist => {}
                    Some(_) => notes.push(format!("{}: чужой файл сохранён", path.display())),
                    None => {
                        if let Some(parent) = path.parent() {
                            if !parent.exists() {
                                create_private_directory(parent)?;
                            }
                        }
                        state.agent = true;
                        save(&state)?;
                        robust_write_file(&path, plist.as_bytes())?;
                    }
                }
                notes.push("App: CLOUD_CODE_URL сессии указывает на daily".into());
            }
        }

        for (path, create) in profiles() {
            let existing = read_profile(&path)?;
            if existing.is_none() && !create {
                continue;
            }
            let text = existing.clone().unwrap_or_default();
            let Some(updated) = with_block(&text) else {
                notes.push(format!(
                    "{}: собственный CLOUD_CODE_URL сохранён",
                    path.display()
                ));
                continue;
            };
            if updated == text {
                continue;
            }
            if !state.profiles.iter().any(|profile| profile.path == path) {
                state.profiles.push(Profile {
                    path: path.clone(),
                    created: existing.is_none(),
                });
                save(&state)?;
            }
            robust_write_file(&path, updated.as_bytes())?;
            notes.push(format!("CLI: CLOUD_CODE_URL добавлен в {}", path.display()));
        }
        Ok(notes.join("; "))
    }

    /// The CLI picks up daily in new terminals.
    pub fn cli_configured() -> bool {
        read_profile(&profiles()[0].0)
            .ok()
            .flatten()
            .is_some_and(|text| without_block(&text) != text)
    }

    pub fn restore() -> Result<(), String> {
        let Some(state) = load()? else {
            return Ok(());
        };
        let mut errors = Vec::new();
        for profile in &state.profiles {
            let result = read_profile(&profile.path).and_then(|text| {
                let Some(text) = text else {
                    return Ok(());
                };
                let cleaned = without_block(&text);
                if cleaned == text {
                    Ok(())
                } else if profile.created && cleaned.trim().is_empty() {
                    fs::remove_file(&profile.path).map_err(|e| e.to_string())
                } else {
                    robust_write_file(&profile.path, cleaned.as_bytes())
                }
            });
            if let Err(error) = result {
                errors.push(format!("{}: {error}", profile.path.display()));
            }
        }
        if state.agent {
            let path = agent_path();
            if read_profile(&path).is_ok_and(|text| text.as_deref() == Some(agent_plist().as_str()))
            {
                if let Err(error) = fs::remove_file(&path) {
                    errors.push(format!("{}: {error}", path.display()));
                }
            }
        }
        if let Some(original) = &state.session_original {
            match session::read() {
                Ok(current) if current.as_deref() == Some(DAILY) => {
                    if let Err(error) = session::write(original.as_deref()) {
                        errors.push(error);
                    }
                }
                Ok(_) => {}
                Err(error) => errors.push(error),
            }
        }
        if !errors.is_empty() {
            return Err(errors.join("; "));
        }
        match fs::remove_file(state_path()) {
            Err(error) if error.kind() != ErrorKind::NotFound => Err(error.to_string()),
            _ => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn block_is_added_once_and_removed_exactly() {
        for original in ["", "export PATH=\"$HOME/bin:$PATH\"\n", "alias ll='ls -l'"] {
            let added = with_block(original).unwrap();
            assert!(added.contains(&format!("export CLOUD_CODE_URL=\"{DAILY}\"")));
            assert_eq!(with_block(&added).unwrap(), added);
            let removed = without_block(&added);
            let expected = if original.is_empty() || original.ends_with('\n') {
                original.to_string()
            } else {
                format!("{original}\n")
            };
            assert_eq!(removed, expected);
        }
    }

    #[test]
    fn user_edits_around_the_block_survive_rollback() {
        let added = with_block("# mine\n").unwrap();
        let edited = format!("{added}export EDITOR=vim\r\n");
        assert_eq!(without_block(&edited), "# mine\nexport EDITOR=vim\r\n");
        let crlf = edited.replace(&format!("{END}\n"), &format!("{END}\r\n"));
        assert_eq!(without_block(&crlf), "# mine\nexport EDITOR=vim\r\n");
    }

    #[test]
    fn users_own_endpoint_and_broken_blocks_are_left_alone() {
        assert!(with_block("export CLOUD_CODE_URL=https://custom.example\n").is_none());
        let broken = format!("{BEGIN}\nexport CLOUD_CODE_URL=x\n");
        assert_eq!(without_block(&broken), broken);
        assert!(with_block(&broken).is_none());
    }

    #[test]
    fn launch_agent_sets_daily_at_login() {
        let plist = agent_plist();
        assert!(plist.contains(&format!("<string>{AGENT_LABEL}</string>")));
        assert!(plist.contains(&format!("<string>{DAILY}</string>")));
        assert!(plist.contains("<key>RunAtLoad</key>"));
    }
}
