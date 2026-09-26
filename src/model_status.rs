//! Passive, bounded inspection of recent language-server logs. Never exports log text.
use serde::Serialize;
use std::{
    fs::{self, File},
    io::{Read, Seek, SeekFrom},
    path::{Path, PathBuf},
    sync::OnceLock,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

const FRESH_SECONDS: i64 = 15 * 60;
const TAIL_BYTES: u64 = 256 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum State {
    Disabled,
    NoLogs,
    NoRecentEvents,
    Unreadable,
    StreamStarted,
    RegionBlocked,
    VerificationRequired,
    RequestFailed,
}

#[derive(Clone, Debug, Serialize)]
pub struct Observation {
    pub state: State,
    pub observed_at: Option<i64>,
    pub last_failure: Option<Event>,
    pub files_checked: usize,
    pub partial: bool,
    pub completion_confirmed: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct Event {
    pub state: State,
    pub timestamp: i64,
}

impl Observation {
    fn empty(state: State) -> Self {
        Self {
            state,
            observed_at: None,
            last_failure: None,
            files_checked: 0,
            partial: false,
            completion_confirmed: false,
        }
    }
    pub fn label(&self) -> &'static str {
        match self.state {
            State::Disabled => "Наблюдение отключено",
            State::NoLogs => "Журналы не найдены",
            State::NoRecentEvents => "Нет свежих событий",
            State::Unreadable => "Журналы недоступны",
            State::StreamStarted => "В журнале: начало ответа",
            State::RegionBlocked => "В журнале: отказ по региону",
            State::VerificationRequired => "В журнале: нужна верификация",
            State::RequestFailed => "В журнале: ошибка запроса",
        }
    }
    pub fn warning(&self) -> bool {
        matches!(
            self.state,
            State::Unreadable
                | State::RegionBlocked
                | State::VerificationRequired
                | State::RequestFailed
        )
    }
}

pub fn snapshot() -> Observation {
    let Ok(config) = crate::net::config::load() else {
        return Observation::empty(State::Unreadable);
    };
    from_config(&config)
}

fn from_config(config: &crate::net::config::Config) -> Observation {
    if !config.watch_region_errors {
        return Observation::empty(State::Disabled);
    }
    scan(
        &config.log_roots,
        time::OffsetDateTime::now_utc().unix_timestamp(),
        local_offset(),
    )
}

// Logs without an explicit zone use the machine's current wall clock. Only a
// 15-minute window is inspected; full timestamps with an offset take precedence.
fn local_offset() -> time::UtcOffset {
    #[cfg(windows)]
    {
        use windows_sys::Win32::{Foundation::SYSTEMTIME, System::SystemInformation::GetLocalTime};
        let mut st: SYSTEMTIME = unsafe { std::mem::zeroed() };
        unsafe { GetLocalTime(&mut st) };
        if let Some(wall) = date_time(
            st.wYear as i32,
            st.wMonth as u8,
            st.wDay as u8,
            st.wHour as u8,
            st.wMinute as u8,
            st.wSecond as u8,
        ) {
            let offset = wall.assume_utc().unix_timestamp()
                - time::OffsetDateTime::now_utc().unix_timestamp();
            // Calls can straddle a second boundary; time zones are whole minutes.
            if let Ok(offset) =
                time::UtcOffset::from_whole_seconds(((offset as f64 / 60.0).round() * 60.0) as i32)
            {
                return offset;
            }
        }
    }
    #[cfg(unix)]
    {
        let epoch = time::OffsetDateTime::now_utc().unix_timestamp() as libc::time_t;
        let mut tm: libc::tm = unsafe { std::mem::zeroed() };
        if !unsafe { libc::localtime_r(&epoch, &mut tm) }.is_null() {
            if let Ok(offset) = time::UtcOffset::from_whole_seconds(tm.tm_gmtoff as i32) {
                return offset;
            }
        }
    }
    time::UtcOffset::UTC
}

fn date_time(
    year: i32,
    month: u8,
    day: u8,
    hour: u8,
    minute: u8,
    second: u8,
) -> Option<time::PrimitiveDateTime> {
    Some(
        time::Date::from_calendar_date(year, month.try_into().ok()?, day)
            .ok()?
            .with_time(time::Time::from_hms(hour, minute, second).ok()?),
    )
}

fn timestamp(line: &str, now: i64, offset: time::UtcOffset) -> Option<(i64, &str)> {
    static ISO: OnceLock<regex::Regex> = OnceLock::new();
    static GO: OnceLock<regex::Regex> = OnceLock::new();
    let iso = ISO.get_or_init(|| regex::Regex::new(r"^\[?([0-9]{4})-([0-9]{2})-([0-9]{2})[T ]([0-9]{2}):([0-9]{2}):([0-9]{2})(?:\.[0-9]{1,9})?(Z|[+-][0-9]{2}:?[0-9]{2})?\]?[ \t]+").unwrap());
    if let Some(c) = iso.captures(line) {
        let date = date_time(
            c[1].parse().ok()?,
            c[2].parse().ok()?,
            c[3].parse().ok()?,
            c[4].parse().ok()?,
            c[5].parse().ok()?,
            c[6].parse().ok()?,
        )?;
        let zone = if let Some(zone) = c.get(7) {
            if zone.as_str() == "Z" {
                time::UtcOffset::UTC
            } else {
                let zone = zone.as_str().replace(':', "");
                let sign = if zone.starts_with('-') { -1 } else { 1 };
                time::UtcOffset::from_hms(
                    sign * zone[1..3].parse::<i8>().ok()?,
                    sign * zone[3..5].parse::<i8>().ok()?,
                    0,
                )
                .ok()?
            }
        } else {
            offset
        };
        return Some((
            date.assume_offset(zone).unix_timestamp(),
            &line[c.get(0)?.end()..],
        ));
    }
    let go = GO.get_or_init(|| regex::Regex::new(r"^[IWEF]([0-9]{2})([0-9]{2}) ([0-9]{2}):([0-9]{2}):([0-9]{2})(?:\.[0-9]+)?[ \t]+[0-9]+[ \t]+[^[ \t]\]]+\.go:[0-9]+\][ \t]*").unwrap());
    let c = go.captures(line)?;
    let year = time::OffsetDateTime::from_unix_timestamp(now)
        .ok()?
        .to_offset(offset)
        .year();
    // Go logs omit the year. At New Year choose the closest plausible occurrence.
    let date = [year - 1, year, year + 1]
        .into_iter()
        .filter_map(|year| {
            Some(
                date_time(
                    year,
                    c[1].parse().ok()?,
                    c[2].parse().ok()?,
                    c[3].parse().ok()?,
                    c[4].parse().ok()?,
                    c[5].parse().ok()?,
                )?
                .assume_offset(offset)
                .unix_timestamp(),
            )
        })
        .min_by_key(|date| date.abs_diff(now))?;
    Some((date, &line[c.get(0)?.end()..]))
}

fn event(line: &str, now: i64, offset: time::UtcOffset) -> Option<Event> {
    // A prompt, URL, arbitrary 403, or untimestamped text is not evidence.
    let (timestamp, message) = timestamp(line, now, offset)?;
    if timestamp > now + 5 || now - timestamp > FRESH_SECONDS {
        return None;
    }
    let message = message.to_ascii_lowercase();
    if [
        "received prompt:",
        "prompt=",
        "\"prompt\":",
        "\"messages\":",
        "request body:",
    ]
    .iter()
    .any(|marker| message.contains(marker))
    {
        return None;
    }
    let rpc = message.contains("streamgeneratecontent")
        || message.contains("cascade")
        || message.contains("language server");
    let error = message.contains("error")
        || message.contains("failed")
        || message.contains("permission_denied")
        || message.contains("permissiondenied");
    let state = if rpc
        && error
        && (message.contains("not available in your location")
            || message.contains("not available in your region")
            || message.contains("unsupported location")
            || message.contains("user location is not supported")
            || message.contains("not supported in your region")
            || message.contains("region is not supported"))
    {
        State::RegionBlocked
    } else if rpc
        && error
        && (message.contains("verify your account")
            || message.contains("verification required")
            || message.contains("validation_required"))
    {
        State::VerificationRequired
    } else if rpc && error {
        State::RequestFailed
    } else if message.contains("streamgeneratecontent") && message.contains("responseid") {
        State::StreamStarted
    } else {
        return None;
    };
    Some(Event { state, timestamp })
}

fn supported(path: &Path) -> bool {
    let name = path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    (name.ends_with(".log") || name.contains(".log."))
        && (name.contains("language_server")
            || name.contains("language-server")
            || name.contains("antigravity"))
}

fn discover(roots: &[PathBuf], deadline: Instant) -> (Vec<(SystemTime, PathBuf)>, bool) {
    let mut stack: Vec<_> = roots.iter().map(|p| (p.clone(), 0)).collect();
    let mut files = Vec::new();
    let mut partial = false;
    let mut visited = 0;
    while let Some((path, depth)) = stack.pop() {
        if visited >= 2048 || Instant::now() >= deadline {
            partial = true;
            break;
        }
        visited += 1;
        let meta = match fs::symlink_metadata(&path) {
            Ok(meta) => meta,
            Err(e) => {
                partial |= e.kind() != std::io::ErrorKind::NotFound;
                continue;
            }
        };
        if meta.file_type().is_symlink() {
            continue;
        }
        if meta.is_file() && supported(&path) {
            files.push((meta.modified().unwrap_or(UNIX_EPOCH), path));
        } else if meta.is_dir() && depth < 8 {
            match fs::read_dir(&path) {
                Ok(entries) => {
                    let capacity = 2048usize.saturating_sub(visited + stack.len());
                    for (i, entry) in entries.take(capacity + 1).enumerate() {
                        if i == capacity {
                            partial = true;
                            break;
                        }
                        match entry {
                            Ok(entry) => stack.push((entry.path(), depth + 1)),
                            Err(_) => partial = true,
                        }
                    }
                }
                Err(_) => partial = true,
            }
        }
    }
    files.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.cmp(&b.1)));
    if files.len() > 32 {
        files.truncate(32);
        partial = true;
    }
    (files, partial)
}

fn scan(roots: &[PathBuf], now: i64, offset: time::UtcOffset) -> Observation {
    let deadline = Instant::now() + Duration::from_millis(800);
    let (files, partial) = discover(roots, deadline);
    let mut result = Observation::empty(if files.is_empty() {
        if partial {
            State::Unreadable
        } else {
            State::NoLogs
        }
    } else {
        State::NoRecentEvents
    });
    result.partial = partial;
    let mut remaining = 2 * 1024 * 1024u64;
    for (modified, path) in files {
        // Go timestamps omit the year. A year-old rotated file must not be
        // interpreted as today's request just because month/day/time match.
        if modified
            .duration_since(UNIX_EPOCH)
            .ok()
            .is_none_or(|t| (t.as_secs() as i64) < now - FRESH_SECONDS)
        {
            continue;
        }
        if Instant::now() >= deadline || remaining == 0 {
            result.partial = true;
            break;
        }
        let read = || -> std::io::Result<(Vec<u8>, bool)> {
            let mut file = File::open(&path)?;
            let len = file.metadata()?.len();
            let start = len.saturating_sub(TAIL_BYTES.min(remaining));
            file.seek(SeekFrom::Start(start))?;
            let mut bytes = Vec::new();
            file.take(len - start).read_to_end(&mut bytes)?;
            Ok((bytes, start != 0))
        };
        let Ok((bytes, truncated)) = read() else {
            result.partial = true;
            continue;
        };
        remaining = remaining.saturating_sub(bytes.len() as u64);
        result.files_checked += 1;
        let text = String::from_utf8_lossy(&bytes);
        let mut lines = text.lines();
        if truncated {
            lines.next();
        }
        if !text.ends_with('\n') {
            lines.next_back();
        }
        for line in lines {
            if Instant::now() >= deadline {
                result.partial = true;
                break;
            }
            if line.len() > 16 * 1024 {
                continue;
            }
            if let Some(event) = event(line, now, offset) {
                if result.observed_at.is_none_or(|at| {
                    event.timestamp > at
                        || (event.timestamp == at && event.state != State::StreamStarted)
                }) {
                    result.state = event.state;
                    result.observed_at = Some(event.timestamp);
                }
                if event.state != State::StreamStarted
                    && result
                        .last_failure
                        .as_ref()
                        .is_none_or(|old| event.timestamp > old.timestamp)
                {
                    result.last_failure = Some(event);
                }
            }
        }
    }
    if result.files_checked == 0 && result.partial {
        result.state = State::Unreadable;
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    fn now() -> i64 {
        date_time(2026, 9, 26, 12, 0, 0)
            .unwrap()
            .assume_utc()
            .unix_timestamp()
    }
    #[test]
    fn signals_are_recent_specific_and_never_claim_completion() {
        let parse = |s: &str| event(s, now(), time::UtcOffset::UTC).map(|e| e.state);
        assert_eq!(parse("I0926 11:59:00.123456 123 client.go:42] StreamGenerateContent ResponseID: private-id"), Some(State::StreamStarted));
        assert_eq!(parse("2026-09-26T14:59:00+03:00 [error] StreamGenerateContent: service not available in your location"), Some(State::RegionBlocked));
        assert_eq!(
            parse("2026-09-26T11:59:00Z [error] StreamGenerateContent: verify your account"),
            Some(State::VerificationRequired)
        );
        assert_eq!(
            parse("2026-09-26T11:59:00Z [error] StreamGenerateContent: quota exceeded"),
            Some(State::RequestFailed)
        );
        for s in [
            "StreamGenerateContent ResponseID: old",
            "2026-09-26T11:00:00Z StreamGenerateContent ResponseID: old",
            "2026-09-26T12:10:00Z StreamGenerateContent ResponseID: future",
            "2026-09-26T11:59:00Z HTTP 403",
            "2026-09-26T11:59:00Z INFO received prompt: region is not supported",
        ] {
            assert_eq!(parse(s), None, "{s}");
        }
    }
    #[test]
    fn rotation_chronology_privacy_and_disabled_config() {
        let dir = tempfile::tempdir().unwrap();
        let mut config = crate::net::config::Config::default();
        config.log_roots = vec![dir.path().into()];
        config.watch_region_errors = false;
        let disabled = from_config(&config);
        assert_eq!(disabled.state, State::Disabled);
        assert_eq!(disabled.files_checked, 0);
        fs::write(dir.path().join("language_server.log.1"), "2026-09-26T11:58:00Z [error] StreamGenerateContent: not available in your location token=SECRET text=PRIVATE\n").unwrap();
        fs::write(
            dir.path().join("language_server.log"),
            "2026-09-26T11:59:00Z StreamGenerateContent ResponseID: PRIVATE-ID\n",
        )
        .unwrap();
        fs::write(
            dir.path().join("other.log"),
            "2026-09-26T12:00:00Z [error] StreamGenerateContent: failed\n",
        )
        .unwrap();
        // Make file timestamps deterministic, independent of the test machine's date.
        for file in fs::read_dir(dir.path()).unwrap() {
            File::options()
                .write(true)
                .open(file.unwrap().path())
                .unwrap()
                .set_modified(UNIX_EPOCH + Duration::from_secs(now() as u64))
                .unwrap();
        }
        let observation = scan(&[dir.path().into()], now(), time::UtcOffset::UTC);
        assert_eq!(observation.state, State::StreamStarted);
        assert_eq!(
            observation.last_failure.as_ref().unwrap().state,
            State::RegionBlocked
        );
        assert!(!observation.completion_confirmed);
        let json = serde_json::to_string(&observation).unwrap();
        for secret in [
            "PRIVATE",
            "SECRET",
            "language_server",
            &dir.path().display().to_string(),
        ] {
            assert!(!json.contains(secret));
        }
        assert_eq!(
            scan(&[dir.path().into()], now() + 3600, time::UtcOffset::UTC).state,
            State::NoRecentEvents
        );
        fs::write(dir.path().join("language_server.log"), "incomplete\n").unwrap();
        assert_eq!(
            scan(&[dir.path().into()], now(), time::UtcOffset::UTC).state,
            State::RegionBlocked
        );
    }
    #[test]
    fn new_year_and_local_timezone_are_resolved() {
        let now = date_time(2027, 1, 1, 0, 1, 0)
            .unwrap()
            .assume_utc()
            .unix_timestamp();
        assert!(event(
            "I1231 23:59:00.0 1 file.go:1] StreamGenerateContent ResponseID: x",
            now,
            time::UtcOffset::UTC
        )
        .is_some());
        let offset = time::UtcOffset::from_hms(3, 0, 0).unwrap();
        assert!(event(
            "2027-01-01 03:00:00 StreamGenerateContent ResponseID: x",
            now,
            offset
        )
        .is_some());
    }

    #[test]
    fn old_rotations_partial_lines_and_logged_prompts_are_not_live_events() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("language_server.log");
        fs::write(
            &path,
            "I0926 11:59:00.0 1 file.go:1] StreamGenerateContent ResponseID: old\n",
        )
        .unwrap();
        File::options()
            .write(true)
            .open(&path)
            .unwrap()
            .set_modified(UNIX_EPOCH + Duration::from_secs((now() - 365 * 86400) as u64))
            .unwrap();
        assert_eq!(
            scan(&[dir.path().into()], now(), time::UtcOffset::UTC).state,
            State::NoRecentEvents
        );
        fs::write(
            &path,
            "2026-09-26T11:59:00Z StreamGenerateContent ResponseID: incomplete",
        )
        .unwrap();
        File::options()
            .write(true)
            .open(&path)
            .unwrap()
            .set_modified(UNIX_EPOCH + Duration::from_secs(now() as u64))
            .unwrap();
        assert_eq!(
            scan(&[dir.path().into()], now(), time::UtcOffset::UTC).state,
            State::NoRecentEvents
        );
        assert!(event(
            "2026-09-26T11:59:00Z received prompt: StreamGenerateContent ResponseID: pretend",
            now(),
            time::UtcOffset::UTC
        )
        .is_none());
    }
}
