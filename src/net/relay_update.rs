use crate::system::{fs_utils::robust_write_file, service::RelayBackup};
use std::{fs, io::ErrorKind, path::PathBuf};

pub(super) struct RelayUpdate {
    previous: RelayBackup,
    settings: Vec<Setting>,
    replacement_attempted: bool,
}

impl RelayUpdate {
    pub(super) fn capture() -> Result<Self, String> {
        let paths = [
            super::config::context_path(),
            super::relay::iface_conf_path(),
            super::relay::upstream_conf_path(),
            super::relay::mode_conf_path(),
            #[cfg(target_os = "linux")]
            super::linux_dns::state_path(),
        ];
        Ok(Self {
            previous: RelayBackup::capture()?,
            settings: paths
                .into_iter()
                .map(Setting::capture)
                .collect::<Result<_, _>>()?,
            replacement_attempted: false,
        })
    }

    pub(super) fn start(&mut self) -> Result<(), String> {
        crate::system::service::enable(self.previous.registered, &mut self.replacement_attempted)
    }

    pub(super) fn rollback(self) -> Result<(), String> {
        if self.replacement_attempted {
            self.previous.stop_replacement()?;
        }
        restore_settings(self.settings)?;
        super::relay::clear_settings_cache();
        if self.replacement_attempted {
            self.previous.restore()?;
        }
        Ok(())
    }
}

struct Setting {
    path: PathBuf,
    before: Option<Vec<u8>>,
}

impl Setting {
    fn capture(path: PathBuf) -> Result<Self, String> {
        let before = read_optional(&path)?;
        Ok(Self { path, before })
    }
}

fn read_optional(path: &std::path::Path) -> Result<Option<Vec<u8>>, String> {
    match fs::read(path) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(None),
        Err(error) => Err(format!("{}: {error}", path.display())),
    }
}

fn restore_settings(settings: Vec<Setting>) -> Result<(), String> {
    for Setting { path, before } in settings {
        if read_optional(&path)? != before {
            match before {
                Some(bytes) => robust_write_file(&path, &bytes)?,
                None => fs::remove_file(&path)
                    .map_err(|error| format!("{}: {error}", path.display()))?,
            }
        }
    }
    Ok(())
}

pub(super) fn allow_relay_fallback(
    startup: Result<(), String>,
    has_previous_dns: bool,
    fallback_supported: bool,
) -> Result<Option<String>, String> {
    match startup {
        Ok(()) => Ok(None),
        Err(error) if has_previous_dns || !fallback_supported => Err(error),
        Err(error) => Ok(Some(error)),
    }
}

pub(super) fn finish_staging<T>(
    staged: Result<T, String>,
    rollback: impl FnOnce() -> Result<(), String>,
) -> Result<T, String> {
    staged.map_err(|error| match rollback() {
        Ok(()) => error,
        Err(rollback_error) => {
            format!("{error}. Не удалось полностью восстановить релей: {rollback_error}")
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relay_start_failure_during_upgrade_restores_settings_before_commit() {
        let dir = tempfile::tempdir().unwrap();
        let context = dir.path().join("network-user.json");
        let new_iface = dir.path().join("iface.conf");
        let nrpt = dir.path().join("existing-dns-rules");
        fs::write(&context, b"existing context").unwrap();
        fs::write(&nrpt, b"existing DNS").unwrap();
        let settings = [context.clone(), new_iface.clone()]
            .into_iter()
            .map(Setting::capture)
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        let staged = (|| {
            fs::write(&context, b"replacement context").unwrap();
            fs::write(&new_iface, b"5").unwrap();
            allow_relay_fallback(Err("injected relay start failure".into()), true, true)
        })();
        let result = finish_staging(staged, || restore_settings(settings))
            .and_then(|_| fs::write(&nrpt, b"new DNS rules").map_err(|e| e.to_string()));
        assert_eq!(result.unwrap_err(), "injected relay start failure");
        assert_eq!(fs::read(context).unwrap(), b"existing context");
        assert_eq!(fs::read(nrpt).unwrap(), b"existing DNS");
        assert!(!new_iface.exists());
    }

    #[test]
    fn fresh_install_can_use_a_supported_fallback_or_fail_without_one() {
        let failure = || Err("relay unavailable".into());
        assert_eq!(
            allow_relay_fallback(failure(), false, true),
            Ok(Some("relay unavailable".into()))
        );
        assert_eq!(
            allow_relay_fallback(failure(), false, false),
            failure().map(|_| None)
        );
        assert_eq!(allow_relay_fallback(Ok(()), true, true), Ok(None));
    }
}
