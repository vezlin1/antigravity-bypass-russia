//! DNS rules that follow the VPN.
//!
//! A VPN in TUN mode (sing-box, for example) can block DNS to the local relay.
//! Setup then writes rules without the relay: Antigravity keeps working
//! through `hosts`, but the web versions of Gemini and AI Studio get no
//! bypass. Setup saves the inputs of its rules here; the background service
//! re-checks the relay after every network change and rewrites the same rules
//! with or without the relay, so turning the VPN off enables the bypass for
//! the web versions and turning it on hands them back to the VPN.

use super::{assemble_dns_rules, nrpt, relay, relay_answers, try_configuration_lock};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Inputs of the rules setup applied, as `assemble_dns_rules` takes them.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct SavedRules {
    pub agent: Vec<(String, Vec<String>)>,
    pub studio: Vec<String>,
    pub udp_fallback: Vec<String>,
    pub skip_primary: bool,
    /// Whether the rules currently applied send queries to the relay.
    pub via_relay: bool,
}

impl SavedRules {
    pub fn rules(&self, via_relay: bool) -> Vec<(String, String)> {
        let agent: Vec<(String, Vec<&str>)> = self
            .agent
            .iter()
            .map(|(name, servers)| (name.clone(), servers.iter().map(String::as_str).collect()))
            .collect();
        let studio: Vec<&str> = self.studio.iter().map(String::as_str).collect();
        let fallback: Vec<&str> = self.udp_fallback.iter().map(String::as_str).collect();
        assemble_dns_rules(&agent, &studio, &fallback, via_relay, false)
    }
}

fn path() -> PathBuf {
    relay::log_dir().join("dns-rules.json")
}

pub(super) fn save(saved: &SavedRules) -> Result<(), String> {
    save_at(&path(), saved)
}

fn save_at(path: &Path, saved: &SavedRules) -> Result<(), String> {
    let bytes = serde_json::to_vec_pretty(saved).map_err(|error| error.to_string())?;
    crate::system::fs_utils::robust_write_file(path, &bytes)
}

fn load_at(path: &Path) -> Result<Option<SavedRules>, String> {
    match std::fs::read(path) {
        Ok(bytes) => serde_json::from_slice(&bytes)
            .map(Some)
            .map_err(|error| format!("Сохранённые правила DNS: {error}")),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(format!("Сохранённые правила DNS: {error}")),
    }
}

/// Rollback: without this file the service has nothing to re-apply.
pub(super) fn forget() -> Result<(), String> {
    match std::fs::remove_file(path()) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(format!("Сохранённые правила DNS: {error}")),
    }
}

/// Queries through the relay's DNS address are answered for every Agent
/// host. They travel the same path as the system resolver, so a VPN that
/// blocks local DNS blocks them too. This is setup's own test for using the
/// relay; a stricter one would undo setup's choice right after it.
fn relay_usable(skip_primary: bool, timeout: Duration) -> bool {
    relay_answers(skip_primary, |host| {
        super::relay_returns_address_within(host, timeout)
    })
    .agent_missing
    .is_empty()
}

/// The mode to switch to: a change is accepted only when two checks a moment
/// apart agree, so VPN clients that update routes in several steps do not
/// make the rules flip back and forth.
fn next_mode(applied: bool, first: bool, second: impl FnOnce() -> bool) -> Option<bool> {
    if first == applied {
        return None;
    }
    (second() == first).then_some(first)
}

pub(super) enum Follow {
    /// Rules match the network; nothing to retry.
    Settled,
    /// The network is changing or setup holds the lock; check again soon.
    Retry,
}

/// Called by the background service after a network change.
pub(super) fn follow_network() -> Result<Follow, String> {
    let Some(saved) = load_at(&path())? else {
        return Ok(Follow::Settled);
    };
    let first = relay_usable(saved.skip_primary, Duration::from_millis(1500));
    let Some(via_relay) = next_mode(saved.via_relay, first, || {
        std::thread::sleep(Duration::from_secs(2));
        relay_usable(saved.skip_primary, Duration::from_millis(1500))
    }) else {
        return Ok(if first == saved.via_relay {
            Follow::Settled
        } else {
            Follow::Retry
        });
    };
    let Some(_lock) = try_configuration_lock()? else {
        return Ok(Follow::Retry);
    };
    // Setup may have replaced the rules while this service was checking.
    let Some(mut saved) = load_at(&path())? else {
        return Ok(Follow::Settled);
    };
    if saved.via_relay == via_relay {
        return Ok(Follow::Settled);
    }
    let plan = nrpt::inventory()?.plan(&saved.rules(via_relay));
    nrpt::apply_compatible_rules(&plan, super::provider::NRPT_TAG, "Antigravity DNS")?;
    super::flush_dns_cache()?;
    saved.via_relay = via_relay;
    save(&saved)?;
    relay::log_event(if via_relay {
        "Локальный DNS снова доступен (VPN выключен): Gemini и AI Studio в браузере идут через обход"
    } else {
        "Локальный DNS недоступен (VPN включён): Gemini и AI Studio в браузере переданы VPN"
    });
    Ok(Follow::Settled)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> SavedRules {
        SavedRules {
            agent: vec![(
                "daily-cloudcode-pa.googleapis.com".into(),
                vec!["192.0.2.10".into()],
            )],
            studio: Vec::new(),
            udp_fallback: Vec::new(),
            skip_primary: true,
            via_relay: false,
        }
    }

    #[test]
    fn saved_rules_survive_a_round_trip_and_a_missing_file_means_nothing_to_follow() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("dns-rules.json");
        assert_eq!(load_at(&file).unwrap(), None);
        save_at(&file, &sample()).unwrap();
        assert_eq!(load_at(&file).unwrap(), Some(sample()));
        std::fs::write(&file, b"{").unwrap();
        assert!(load_at(&file).is_err());
    }

    #[test]
    fn relay_mode_adds_the_relay_and_web_rules_without_servers_disappear() {
        let saved = sample();
        let with_relay = saved.rules(true);
        let without = saved.rules(false);
        let servers = |rules: &[(String, String)], name: &str| {
            rules
                .iter()
                .find(|(namespace, _)| namespace == name)
                .map(|(_, servers)| servers.clone())
        };
        assert_eq!(
            servers(&with_relay, "gemini.google.com").as_deref(),
            Some(super::super::LISTEN_IP)
        );
        // Without the relay the web domains have no server: the planner skips
        // them and reconciliation removes the old ones, leaving them to the VPN.
        assert_eq!(servers(&without, "gemini.google.com").as_deref(), Some(""));
        assert_eq!(
            servers(&without, "daily-cloudcode-pa.googleapis.com").as_deref(),
            Some("192.0.2.10")
        );
        let plan = nrpt::NrptInventory::default().plan(&without);
        assert!(plan
            .rules
            .iter()
            .all(|(name, _)| name != "gemini.google.com"));
    }

    #[test]
    fn mode_changes_only_when_two_checks_agree() {
        // No change observed: the second check is not even made.
        assert_eq!(next_mode(false, false, || unreachable!()), None);
        // VPN turned off and stays off.
        assert_eq!(next_mode(false, true, || true), Some(true));
        // VPN turned on and stays on.
        assert_eq!(next_mode(true, false, || false), Some(false));
        // A route flap: the second check disagrees, keep the current rules.
        assert_eq!(next_mode(false, true, || false), None);
    }
}
