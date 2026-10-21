//! CT-01, CT-02: the CLIs' JSON, read field by field.
//!
//! Docker prints one object per line with `--format '{{json .}}'`, its values mostly text (`"Ports":
//! "0.0.0.0:8080->80/tcp"`, `"Size": "187MB"`); Podman prints one array with `--format json`, with
//! arrays, numbers and Unix times instead, and some keys in lower case. Field names are looked up
//! exactly first, then without regard to case, and a missing or unexpected field leaves that value
//! empty rather than failing the list, so versions that add or drop fields still read. An entry
//! whose id (or a volume whose name) does not pass [`super::names`] is left out: nothing from it
//! could be acted on safely.
//!
//! Text from the engine is cleaned of control characters (and logs of ANSI colour codes) before it
//! goes anywhere. Environment values never leave this module: only their names do.

use std::collections::BTreeMap;

use serde_json::{Map, Value};
use time::format_description::well_known::Rfc3339;
use time::macros::format_description;
use time::{OffsetDateTime, PrimitiveDateTime, UtcOffset};

use super::names::{is_log_time, shown, ContainerId, ImageId, VolumeName};
use super::{
    ContainerDetails, ContainerState, ContainerStats, ContainerSummary, EngineVersion, HealthInfo, ImageSummary,
    LogLine, LogStream, MountInfo, NetworkAttachment, NetworkSummary, PortMapping, VolumeSummary,
};
use crate::error::{ContainerProblem, CoreError, Result};

/// The Compose project label (Docker Compose and podman-compose).
const PROJECT_LABEL: &str = "com.docker.compose.project";
/// The most text kept of one value.
const MAX_TEXT: usize = 4096;

fn unreadable(what: &str, detail: impl std::fmt::Display) -> CoreError {
    CoreError::Container {
        problem: ContainerProblem::Unreadable,
        message: format!("Remotely can't read what {what} printed ({detail})"),
    }
}

/// The JSON values in a CLI's output: one array (Podman), one object, or one object per line
/// (Docker). Blank output is an empty list.
pub fn values(what: &str, stdout: &str) -> Result<Vec<Value>> {
    let text = stdout.trim();
    if text.is_empty() {
        return Ok(Vec::new());
    }
    if let Ok(whole) = serde_json::from_str::<Value>(text) {
        return Ok(match whole {
            Value::Array(items) => items,
            Value::Null => Vec::new(),
            other => vec![other],
        });
    }
    text.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(|line| serde_json::from_str::<Value>(line).map_err(|err| unreadable(what, err)))
        .collect()
}

/// Text fit to show: control characters and ANSI escape sequences removed, at most [`MAX_TEXT`].
pub fn clean(text: &str) -> String {
    let mut out = String::with_capacity(text.len().min(MAX_TEXT));
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\x1b' {
            // CSI (`ESC [ ... final`) or a two-character escape.
            if chars.peek() == Some(&'[') {
                chars.next();
                for n in chars.by_ref() {
                    if ('\x40'..='\x7e').contains(&n) {
                        break;
                    }
                }
            } else {
                chars.next();
            }
            continue;
        }
        if c == '\t' {
            out.push(' ');
        } else if !c.is_control() {
            out.push(c);
        }
        if out.len() >= MAX_TEXT {
            break;
        }
    }
    out
}

fn object(value: &Value) -> Option<&Map<String, Value>> {
    value.as_object()
}

/// A field by any of its names: exact first, then ignoring case. Null counts as missing.
fn get<'a>(value: &'a Value, keys: &[&str]) -> Option<&'a Value> {
    let map = object(value)?;
    keys.iter()
        .find_map(|key| map.get(*key).filter(|v| !v.is_null()))
        .or_else(|| {
            keys.iter().find_map(|key| {
                map.iter()
                    .find(|(k, v)| k.eq_ignore_ascii_case(key) && !v.is_null())
                    .map(|(_, v)| v)
            })
        })
}

/// A value as text; numbers and booleans too. Empty, `<none>` and `N/A` count as missing.
fn as_text(value: &Value) -> Option<String> {
    let text = match value {
        Value::String(s) => clean(s.trim()),
        Value::Number(n) => n.to_string(),
        Value::Bool(b) => b.to_string(),
        _ => return None,
    };
    let text = text.trim().to_owned();
    (!text.is_empty() && text != "<none>" && text != "N/A" && text != "--").then_some(text)
}

fn text(value: &Value, keys: &[&str]) -> Option<String> {
    get(value, keys).and_then(as_text)
}

/// A list: an array, or text separated by commas.
fn texts(value: &Value, keys: &[&str]) -> Vec<String> {
    match get(value, keys) {
        Some(Value::Array(items)) => items.iter().filter_map(as_text).collect(),
        Some(other) => as_text(other)
            .map(|t| {
                t.split(',')
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(str::to_owned)
                    .collect()
            })
            .unwrap_or_default(),
        None => Vec::new(),
    }
}

/// A number, from a number or from text like `0.15%`.
fn number(value: &Value, keys: &[&str]) -> Option<f64> {
    match get(value, keys)? {
        Value::Number(n) => n.as_f64(),
        Value::String(s) => s.trim().trim_end_matches('%').trim().parse().ok(),
        _ => None,
    }
    .filter(|n: &f64| n.is_finite())
}

fn integer(value: &Value, keys: &[&str]) -> Option<i64> {
    match get(value, keys)? {
        Value::Number(n) => n.as_i64().or_else(|| n.as_f64().map(|f| f as i64)),
        Value::String(s) => s.trim().parse().ok(),
        _ => None,
    }
}

fn boolean(value: &Value, keys: &[&str]) -> Option<bool> {
    match get(value, keys)? {
        Value::Bool(b) => Some(*b),
        Value::String(s) => match s.trim().to_ascii_lowercase().as_str() {
            "true" => Some(true),
            "false" => Some(false),
            _ => None,
        },
        _ => None,
    }
}

/// Labels: an object (Podman, inspect) or `k=v,k=v` text (Docker's lists).
fn labels(value: &Value, keys: &[&str]) -> BTreeMap<String, String> {
    match get(value, keys) {
        Some(Value::Object(map)) => map
            .iter()
            .filter_map(|(k, v)| as_text(v).map(|v| (clean(k), v)))
            .collect(),
        Some(Value::String(s)) => s
            .split(',')
            .filter_map(|pair| pair.split_once('='))
            .map(|(k, v)| (clean(k.trim()), clean(v.trim())))
            .collect(),
        _ => BTreeMap::new(),
    }
}

fn project(value: &Value, keys: &[&str]) -> Option<String> {
    labels(value, keys).remove(PROJECT_LABEL).filter(|p| !p.is_empty())
}

/// A time as RFC 3339 (UTC): Unix seconds (Podman), RFC 3339 (inspect), or Docker's list form
/// `2026-10-21 10:00:00 +0000 UTC`. Docker's "never" (year 1) and 0 are missing.
pub fn time_of(value: &Value) -> Option<String> {
    let at = match value {
        Value::Number(n) => {
            let secs = n.as_i64().or_else(|| n.as_f64().map(|f| f as i64))?;
            if secs <= 0 {
                return None;
            }
            // Milliseconds from some versions.
            let secs = if secs > 100_000_000_000 { secs / 1000 } else { secs };
            OffsetDateTime::from_unix_timestamp(secs).ok()?
        }
        Value::String(s) => parse_time(s.trim())?,
        _ => return None,
    };
    if at.year() < 1971 {
        return None;
    }
    at.to_offset(UtcOffset::UTC).format(&Rfc3339).ok()
}

fn parse_time(text: &str) -> Option<OffsetDateTime> {
    if let Ok(at) = OffsetDateTime::parse(text, &Rfc3339) {
        return Some(at);
    }
    // `2026-10-21 10:00:00[.123] +0000 UTC`: date, time, offset, then a zone name to drop.
    let mut words: Vec<&str> = text.split_whitespace().collect();
    if words.len() == 4 && words[3].chars().all(|c| c.is_ascii_alphabetic()) {
        words.pop();
    }
    let [date, clock, offset] = words.as_slice() else {
        return None;
    };
    let clock = clock.split('.').next().unwrap_or(clock);
    let local = PrimitiveDateTime::parse(
        &format!("{date} {clock}"),
        format_description!("[year]-[month]-[day] [hour]:[minute]:[second]"),
    )
    .ok()?;
    let sign = match offset.chars().next()? {
        '+' => 1,
        '-' => -1,
        _ => return None,
    };
    let digits = &offset[1..];
    if digits.len() != 4 || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let hours: i8 = digits[..2].parse().ok()?;
    let minutes: i8 = digits[2..].parse().ok()?;
    let offset = UtcOffset::from_hms(sign * hours, sign * minutes, 0).ok()?;
    Some(local.assume_offset(offset))
}

fn time(value: &Value, keys: &[&str]) -> Option<String> {
    get(value, keys).and_then(time_of)
}

/// Bytes from `5.3MiB`, `1.2kB`, `187MB`, `0B` (decimal and binary units) or a number.
pub fn size_bytes(text: &str) -> Option<u64> {
    let text = text.trim();
    let split = text
        .find(|c: char| !(c.is_ascii_digit() || c == '.'))
        .unwrap_or(text.len());
    let (amount, unit) = text.split_at(split);
    let amount: f64 = amount.parse().ok()?;
    let factor: f64 = match unit.trim().to_ascii_lowercase().as_str() {
        "" | "b" => 1.0,
        "kb" | "k" => 1e3,
        "mb" | "m" => 1e6,
        "gb" | "g" => 1e9,
        "tb" | "t" => 1e12,
        "kib" => 1024.0,
        "mib" => 1024.0 * 1024.0,
        "gib" => 1024.0 * 1024.0 * 1024.0,
        "tib" => 1024.0 * 1024.0 * 1024.0 * 1024.0,
        _ => return None,
    };
    Some((amount * factor).round() as u64)
}

fn bytes(value: &Value, keys: &[&str]) -> Option<u64> {
    match get(value, keys)? {
        Value::Number(n) => n.as_u64().or_else(|| n.as_f64().map(|f| f.max(0.0) as u64)),
        Value::String(s) => size_bytes(s),
        _ => None,
    }
}

/// `5.3MiB / 7.6GiB`: both sides.
fn pair(value: &Value, keys: &[&str]) -> (Option<u64>, Option<u64>) {
    match get(value, keys) {
        Some(Value::String(s)) => match s.split_once('/') {
            Some((a, b)) => (size_bytes(a), size_bytes(b)),
            None => (size_bytes(s), None),
        },
        Some(Value::Number(n)) => (n.as_u64(), None),
        _ => (None, None),
    }
}

/// Docker's port list: `0.0.0.0:8080->80/tcp, :::8080->80/tcp, 443/tcp, 0.0.0.0:7000-7001->7000-7001/tcp`.
pub fn docker_ports(text: &str) -> Vec<PortMapping> {
    let mut out = Vec::new();
    for item in text.split(',').map(str::trim).filter(|s| !s.is_empty()) {
        let (published, inside) = match item.split_once("->") {
            Some((p, i)) => (Some(p), i),
            None => (None, item),
        };
        let (inside_ports, protocol) = inside.split_once('/').unwrap_or((inside, "tcp"));
        let Some(inside) = port_range(inside_ports) else {
            continue;
        };
        let (host_ip, host) = match published {
            Some(p) => match p.rsplit_once(':') {
                Some((ip, port)) => (Some(ip.trim_matches(['[', ']']).to_owned()), port_range(port)),
                None => (None, port_range(p)),
            },
            None => (None, None),
        };
        for (i, container_port) in inside.into_iter().enumerate() {
            out.push(PortMapping {
                host_ip: host_ip.clone(),
                host_port: host.as_ref().and_then(|h| h.get(i).copied()),
                container_port,
                protocol: clean(protocol),
            });
        }
    }
    dedupe_ports(out)
}

/// `80` or `7000-7001` (at most 64 ports).
fn port_range(text: &str) -> Option<Vec<u16>> {
    let (start, end) = match text.trim().split_once('-') {
        Some((a, b)) => (a.parse::<u16>().ok()?, b.parse::<u16>().ok()?),
        None => {
            let p = text.trim().parse::<u16>().ok()?;
            (p, p)
        }
    };
    (start <= end).then(|| (start..=end).take(64).collect())
}

/// Docker lists a port published on every address twice, for IPv4 and IPv6: keep one.
fn dedupe_ports(ports: Vec<PortMapping>) -> Vec<PortMapping> {
    let any = |ip: &Option<String>| matches!(ip.as_deref(), None | Some("" | "0.0.0.0" | "::"));
    let mut out: Vec<PortMapping> = Vec::new();
    for port in ports {
        let twin = out.iter().any(|p| {
            p.host_port == port.host_port
                && p.container_port == port.container_port
                && p.protocol == port.protocol
                && any(&p.host_ip)
                && any(&port.host_ip)
        });
        if !twin {
            out.push(port);
        }
    }
    out
}

/// Podman's port list: `[{"host_ip": "", "container_port": 80, "host_port": 8080, "range": 1, "protocol": "tcp"}]`.
fn podman_ports(items: &[Value]) -> Vec<PortMapping> {
    let mut out = Vec::new();
    for item in items {
        let Some(container) = integer(item, &["container_port", "containerPort"]) else {
            continue;
        };
        let host = integer(item, &["host_port", "hostPort"]);
        let range = integer(item, &["range"]).unwrap_or(1).clamp(1, 64);
        for i in 0..range {
            let Ok(container_port) = u16::try_from(container + i) else {
                continue;
            };
            out.push(PortMapping {
                host_ip: text(item, &["host_ip", "hostIP", "hostIp"]),
                host_port: host.and_then(|h| u16::try_from(h + i).ok()).filter(|p| *p > 0),
                container_port,
                protocol: text(item, &["protocol"]).unwrap_or_else(|| "tcp".into()),
            });
        }
    }
    dedupe_ports(out)
}

fn ports(value: &Value, keys: &[&str]) -> Vec<PortMapping> {
    match get(value, keys) {
        Some(Value::String(s)) => docker_ports(s),
        Some(Value::Array(items)) => podman_ports(items),
        _ => Vec::new(),
    }
}

/// The state from Docker's status text, for versions whose list has no `State`.
fn state_from_status(status: &str) -> ContainerState {
    let s = status.trim().to_ascii_lowercase();
    if s.starts_with("up") {
        if s.contains("(paused)") {
            ContainerState::Paused
        } else {
            ContainerState::Running
        }
    } else if s.starts_with("exited") {
        ContainerState::Exited
    } else if s.starts_with("created") {
        ContainerState::Created
    } else if s.starts_with("restarting") {
        ContainerState::Restarting
    } else if s.starts_with("removal") {
        ContainerState::Removing
    } else if s.starts_with("dead") {
        ContainerState::Dead
    } else {
        ContainerState::Unknown
    }
}

fn health_from_status(status: &str) -> Option<String> {
    let s = status.to_ascii_lowercase();
    if s.contains("(unhealthy)") {
        Some("unhealthy".into())
    } else if s.contains("(healthy)") {
        Some("healthy".into())
    } else if s.contains("health: starting") || s.contains("(starting)") {
        Some("starting".into())
    } else {
        None
    }
}

/// A command as one line: Docker's text (quoted in its list), or Podman's words.
fn command(value: &Value, keys: &[&str]) -> Option<String> {
    match get(value, keys)? {
        Value::Array(words) => {
            let words: Vec<String> = words.iter().filter_map(as_text).collect();
            (!words.is_empty()).then(|| words.join(" "))
        }
        other => as_text(other).map(|t| t.trim_matches('"').to_owned()),
    }
}

fn container_id(value: &Value, keys: &[&str]) -> Option<ContainerId> {
    let id = text(value, keys)?;
    match ContainerId::parse(&id.to_ascii_lowercase()) {
        Ok(id) => Some(id),
        Err(_) => {
            tracing::warn!(id = %shown(&id), "left out a container whose id is not hex");
            None
        }
    }
}

/// `ps -a`.
pub fn containers(stdout: &str) -> Result<Vec<ContainerSummary>> {
    let mut out = Vec::new();
    for item in values("the container list", stdout)? {
        let Some(id) = container_id(&item, &["ID", "Id"]) else {
            continue;
        };
        let names = texts(&item, &["Names", "Name"]);
        let name = names
            .first()
            .map(|n| n.trim_start_matches('/').to_owned())
            .unwrap_or_else(|| id.short().to_owned());
        let mut status = text(&item, &["Status"]).unwrap_or_default();
        let state = match text(&item, &["State"]) {
            Some(state) => match ContainerState::parse(&state) {
                ContainerState::Unknown => state_from_status(&status),
                known => known,
            },
            None => state_from_status(&status),
        };
        if status.is_empty() {
            status = match (state, integer(&item, &["ExitCode"])) {
                (ContainerState::Exited, Some(code)) => format!("Exited ({code})"),
                (state, _) => capitalized(state.as_str()),
            };
        }
        let health = health_from_status(&status);
        out.push(ContainerSummary {
            name,
            image: text(&item, &["Image"]).unwrap_or_else(|| "(unknown image)".into()),
            command: command(&item, &["Command"]),
            state,
            created_at: time(&item, &["CreatedAt", "Created"]).or_else(|| time(&item, &["Created"])),
            started_at: time(&item, &["StartedAt"]),
            ports: ports(&item, &["Ports"]),
            networks: texts(&item, &["Networks"]),
            mounts: texts(&item, &["Mounts"]),
            project: project(&item, &["Labels"]),
            health,
            status,
            id,
        });
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(out)
}

fn capitalized(text: &str) -> String {
    let mut chars = text.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().chain(chars).collect(),
        None => String::new(),
    }
}

/// `stats --no-stream`.
pub fn stats(stdout: &str) -> Result<Vec<ContainerStats>> {
    let mut out = Vec::new();
    for item in values("the container stats", stdout)? {
        let Some(id) = container_id(&item, &["ID", "Id", "ContainerID", "Container"]) else {
            continue;
        };
        let (mut mem, mut limit) = pair(&item, &["MemUsage", "mem_usage"]);
        if mem.is_none() {
            mem = bytes(&item, &["MemUsage", "mem_usage"]);
        }
        if limit.is_none() {
            limit = bytes(&item, &["MemLimit", "mem_limit"]);
        }
        let (net_rx, net_tx) = pair(&item, &["NetIO", "net_io"]);
        let (block_read, block_write) = pair(&item, &["BlockIO", "block_io"]);
        out.push(ContainerStats {
            id,
            name: text(&item, &["Name"]),
            cpu_pct: number(&item, &["CPUPerc", "cpu_percent", "CPU"]),
            mem_bytes: mem,
            mem_limit_bytes: limit,
            mem_pct: number(&item, &["MemPerc", "mem_percent"]),
            net_rx_bytes: net_rx,
            net_tx_bytes: net_tx,
            block_read_bytes: block_read,
            block_write_bytes: block_write,
            pids: integer(&item, &["PIDs", "pids"]).and_then(|n| u64::try_from(n).ok()),
        });
    }
    Ok(out)
}

/// `images`: Docker prints a row per tag, so rows with the same id are one image.
pub fn images(stdout: &str) -> Result<Vec<ImageSummary>> {
    let mut out: Vec<ImageSummary> = Vec::new();
    for item in values("the image list", stdout)? {
        let Some(raw) = text(&item, &["ID", "Id"]) else {
            continue;
        };
        let Ok(id) = ImageId::parse(&raw.to_ascii_lowercase()) else {
            tracing::warn!(id = %shown(&raw), "left out an image whose id is not hex");
            continue;
        };
        let mut tags = Vec::new();
        match get(&item, &["RepoTags"]) {
            Some(Value::Array(list)) => tags.extend(list.iter().filter_map(as_text).filter(|t| !t.contains("<none>"))),
            _ => {
                if let Some(repo) = text(&item, &["Repository"]) {
                    tags.push(match text(&item, &["Tag"]) {
                        Some(tag) => format!("{repo}:{tag}"),
                        None => repo,
                    });
                }
            }
        }
        let size = bytes(&item, &["Size", "VirtualSize"]);
        let containers = integer(&item, &["Containers"]).and_then(|n| u64::try_from(n).ok());
        let dangling = boolean(&item, &["Dangling"]);
        match out.iter_mut().find(|i| i.id.same_as(&id)) {
            Some(known) => {
                for tag in tags {
                    if !known.tags.contains(&tag) {
                        known.tags.push(tag);
                    }
                }
                known.dangling = known.tags.is_empty();
            }
            None => out.push(ImageSummary {
                dangling: dangling.unwrap_or(tags.is_empty()) && tags.is_empty(),
                tags,
                digest: text(&item, &["Digest"]),
                created_at: time(&item, &["CreatedAt", "Created"]).or_else(|| time(&item, &["Created"])),
                size_bytes: size,
                containers,
                id,
            }),
        }
    }
    out.sort_by_key(|a| a.display_name());
    Ok(out)
}

/// `volume ls`.
pub fn volumes(stdout: &str) -> Result<Vec<VolumeSummary>> {
    let mut out = Vec::new();
    for item in values("the volume list", stdout)? {
        let Some(raw) = text(&item, &["Name"]) else {
            continue;
        };
        let Ok(name) = VolumeName::parse(&raw) else {
            tracing::warn!(name = %shown(&raw), "left out a volume whose name Remotely can't pass on");
            continue;
        };
        out.push(VolumeSummary {
            anonymous: name.is_anonymous(),
            driver: text(&item, &["Driver"]),
            mountpoint: text(&item, &["Mountpoint"]),
            scope: text(&item, &["Scope"]),
            created_at: time(&item, &["CreatedAt"]),
            project: project(&item, &["Labels"]),
            name,
        });
    }
    out.sort_by(|a, b| (a.anonymous, &a.name).cmp(&(b.anonymous, &b.name)));
    Ok(out)
}

/// `network ls`.
pub fn networks(stdout: &str) -> Result<Vec<NetworkSummary>> {
    let mut out = Vec::new();
    for item in values("the network list", stdout)? {
        let (Some(id), Some(name)) = (text(&item, &["ID", "id"]), text(&item, &["Name", "name"])) else {
            continue;
        };
        let subnets = match get(&item, &["subnets", "Subnets"]) {
            Some(Value::Array(list)) => list
                .iter()
                .filter_map(|s| text(s, &["subnet", "Subnet"]).or_else(|| as_text(s)))
                .collect(),
            _ => Vec::new(),
        };
        out.push(NetworkSummary {
            id,
            name,
            driver: text(&item, &["Driver", "driver"]),
            scope: text(&item, &["Scope"]),
            internal: boolean(&item, &["Internal", "internal"]),
            ipv6: boolean(&item, &["IPv6", "ipv6_enabled", "EnableIPv6"]),
            subnets,
            created_at: time(&item, &["CreatedAt", "created", "Created"]),
        });
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(out)
}

/// `version`.
pub fn version(stdout: &str) -> Result<EngineVersion> {
    let item = values("the version", stdout)?
        .into_iter()
        .next()
        .ok_or_else(|| unreadable("the version", "no output"))?;
    let client = get(&item, &["Client"]);
    let server = get(&item, &["Server"]);
    let platform = server
        .and_then(|s| match (text(s, &["Os"]), text(s, &["Arch"])) {
            (Some(os), Some(arch)) => Some(format!("{os}/{arch}")),
            _ => text(s, &["OsArch"]),
        })
        .or_else(|| client.and_then(|c| text(c, &["OsArch"])));
    Ok(EngineVersion {
        client: client.and_then(|c| text(c, &["Version"])),
        server: server.and_then(|s| text(s, &["Version"])),
        api: server
            .and_then(|s| text(s, &["ApiVersion", "APIVersion"]))
            .or_else(|| client.and_then(|c| text(c, &["ApiVersion", "APIVersion"]))),
        platform,
    })
}

/// `inspect --type container`: the first (only) entry.
pub fn details(stdout: &str) -> Result<ContainerDetails> {
    let item = values("the container details", stdout)?
        .into_iter()
        .next()
        .ok_or_else(|| unreadable("the container details", "no output"))?;
    let id = container_id(&item, &["Id", "ID"]).ok_or_else(|| unreadable("the container details", "no id"))?;
    let empty = Value::Null;
    let state = get(&item, &["State"]).unwrap_or(&empty);
    let config = get(&item, &["Config"]).unwrap_or(&empty);
    let host_config = get(&item, &["HostConfig"]).unwrap_or(&empty);
    let network_settings = get(&item, &["NetworkSettings"]).unwrap_or(&empty);

    let health = get(state, &["Health", "Healthcheck"]).and_then(|h| {
        text(h, &["Status"]).map(|status| HealthInfo {
            status,
            failing_streak: integer(h, &["FailingStreak"]),
        })
    });
    let restart_policy = get(host_config, &["RestartPolicy"]).map(|policy| {
        let name = text(policy, &["Name"]).unwrap_or_else(|| "no".into());
        match integer(policy, &["MaximumRetryCount"]) {
            Some(n) if n > 0 && name == "on-failure" => format!("{name}:{n}"),
            _ => name,
        }
    });
    let mut env_names: Vec<String> = Vec::new();
    if let Some(Value::Array(env)) = get(config, &["Env"]) {
        for entry in env.iter().filter_map(Value::as_str) {
            // Only the name: the value may be a password.
            let name = clean(entry.split('=').next().unwrap_or_default());
            if !name.is_empty() && !env_names.contains(&name) {
                env_names.push(name);
            }
        }
    }
    let mounts = match get(&item, &["Mounts"]) {
        Some(Value::Array(list)) => list
            .iter()
            .filter_map(|m| {
                Some(MountInfo {
                    kind: text(m, &["Type"]).unwrap_or_else(|| "volume".into()),
                    name: text(m, &["Name"]),
                    source: text(m, &["Source"]),
                    destination: text(m, &["Destination", "Target"])?,
                    read_only: boolean(m, &["RW"]).map(|rw| !rw).unwrap_or(false),
                })
            })
            .collect(),
        _ => Vec::new(),
    };
    let networks = match get(network_settings, &["Networks"]) {
        Some(Value::Object(map)) => map
            .iter()
            .map(|(name, n)| NetworkAttachment {
                name: clean(name),
                ip_address: text(n, &["IPAddress"]),
                gateway: text(n, &["Gateway"]),
            })
            .collect(),
        _ => Vec::new(),
    };
    let mut ports = Vec::new();
    if let Some(Value::Object(map)) = get(network_settings, &["Ports"]) {
        for (inside, published) in map {
            let (port, protocol) = inside.split_once('/').unwrap_or((inside, "tcp"));
            let Ok(container_port) = port.parse::<u16>() else {
                continue;
            };
            match published {
                Value::Array(list) if !list.is_empty() => {
                    for p in list {
                        ports.push(PortMapping {
                            host_ip: text(p, &["HostIp"]),
                            host_port: text(p, &["HostPort"]).and_then(|h| h.parse().ok()),
                            container_port,
                            protocol: clean(protocol),
                        });
                    }
                }
                _ => ports.push(PortMapping {
                    host_ip: None,
                    host_port: None,
                    container_port,
                    protocol: clean(protocol),
                }),
            }
        }
    }
    // The engine's map comes in key order ("443/tcp" before "80/tcp"): by port reads better.
    ports.sort_by(|a, b| (a.container_port, &a.protocol).cmp(&(b.container_port, &b.protocol)));
    let status_word = text(state, &["Status"]).unwrap_or_default();
    let state_value = match ContainerState::parse(&status_word) {
        ContainerState::Unknown if boolean(state, &["Paused"]) == Some(true) => ContainerState::Paused,
        ContainerState::Unknown if boolean(state, &["Running"]) == Some(true) => ContainerState::Running,
        other => other,
    };
    Ok(ContainerDetails {
        name: text(&item, &["Name"])
            .map(|n| n.trim_start_matches('/').to_owned())
            .unwrap_or_else(|| id.short().to_owned()),
        image: text(config, &["Image"])
            .or_else(|| text(&item, &["ImageName"]))
            .or_else(|| text(&item, &["Image"]))
            .unwrap_or_default(),
        image_id: text(&item, &["Image"]),
        created_at: time(&item, &["Created"]),
        started_at: time(state, &["StartedAt"]),
        finished_at: time(state, &["FinishedAt"]),
        state: state_value,
        exit_code: integer(state, &["ExitCode"]),
        error: text(state, &["Error"]),
        oom_killed: boolean(state, &["OOMKilled"]).unwrap_or(false),
        health,
        restart_policy,
        restart_count: integer(&item, &["RestartCount"]),
        command: command(config, &["Cmd"]),
        entrypoint: command(config, &["Entrypoint"]),
        working_dir: text(config, &["WorkingDir"]),
        runs_as: text(config, &["User"]),
        env_names,
        mounts,
        networks,
        ports: dedupe_ports(ports),
        project: project(config, &["Labels"]),
        platform: text(&item, &["Platform"]),
        id,
    })
}

/// `logs --timestamps`: stdout's and stderr's lines merged by time, after `since` when given.
pub fn logs(stdout: &str, stderr: &str, since: Option<&str>) -> Vec<LogLine> {
    let mut lines: Vec<LogLine> = Vec::new();
    for (stream, text) in [(LogStream::Stdout, stdout), (LogStream::Stderr, stderr)] {
        for raw in text.lines() {
            let raw = raw.trim_end_matches('\r');
            let (at, rest) = match raw.split_once(' ') {
                Some((first, rest)) if is_log_time(first) => (Some(first.to_owned()), rest),
                _ if is_log_time(raw) => (Some(raw.to_owned()), ""),
                _ => (None, raw),
            };
            if let (Some(at), Some(since)) = (&at, since) {
                if at.as_str() <= since {
                    continue;
                }
            }
            lines.push(LogLine {
                at,
                stream,
                text: clean(rest),
            });
        }
    }
    // Stable, so lines with the same time keep their order within a stream.
    lines.sort_by(|a, b| a.at.cmp(&b.at));
    lines
}

/// What a prune says it did, for the job's audit entry: "reclaimed 1.2GB", or how many it removed.
pub fn prune_note(stdout: &str) -> Option<String> {
    if let Some(line) = stdout
        .lines()
        .find_map(|l| l.trim().strip_prefix("Total reclaimed space:"))
    {
        return Some(format!("reclaimed {}", clean(line.trim())));
    }
    let removed = stdout
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.ends_with(':'))
        .count();
    Some(match removed {
        0 => "nothing to remove".to_owned(),
        1 => "removed 1".to_owned(),
        n => format!("removed {n}"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const ID1: &str = "1a2b3c4d5e6f1a2b3c4d5e6f1a2b3c4d5e6f1a2b3c4d5e6f1a2b3c4d5e6f1a2b";
    const ID2: &str = "abcdefabcdef00000000000000000000000000000000000000000000000000ff";
    const IMG: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    #[test]
    fn docker_lists_one_object_per_line() {
        let out = format!(
            concat!(
                r#"{{"Command":"\"/docker-entrypoint.sh nginx -g 'daemon off;'\"","CreatedAt":"2026-10-20 09:30:00 +0000 UTC","ID":"{}","Image":"nginx:1.27","Labels":"com.docker.compose.project=shop,com.docker.compose.service=web","LocalVolumes":"0","Mounts":"shop_static","Names":"shop-web-1","Networks":"shop_default","Ports":"0.0.0.0:8080->80/tcp, :::8080->80/tcp, 443/tcp","RunningFor":"25 hours ago","Size":"0B","State":"running","Status":"Up 25 hours (healthy)"}}"#,
                "\n",
                r#"{{"Command":"\"docker-entrypoint.sh postgres\"","CreatedAt":"2026-10-01 08:00:00 +0200 CEST","ID":"{}","Image":"postgres:16","Labels":"","Mounts":"pgdata","Names":"db","Networks":"bridge","Ports":"","State":"exited","Status":"Exited (0) 3 days ago"}}"#,
                "\n"
            ),
            ID1, ID2
        );
        let list = containers(&out).unwrap();
        assert_eq!(list.len(), 2);
        let db = &list[0];
        assert_eq!(db.name, "db");
        assert_eq!(db.state, ContainerState::Exited);
        assert_eq!(db.created_at.as_deref(), Some("2026-10-01T06:00:00Z"));
        assert!(db.ports.is_empty());
        assert_eq!(db.mounts, ["pgdata"]);
        let web = &list[1];
        assert_eq!(web.id.as_str(), ID1);
        assert_eq!(web.name, "shop-web-1");
        assert_eq!(web.image, "nginx:1.27");
        assert_eq!(web.state, ContainerState::Running);
        assert_eq!(web.health.as_deref(), Some("healthy"));
        assert_eq!(web.project.as_deref(), Some("shop"));
        assert_eq!(
            web.command.as_deref(),
            Some("/docker-entrypoint.sh nginx -g 'daemon off;'")
        );
        let ports: Vec<String> = web.ports.iter().map(PortMapping::describe).collect();
        assert_eq!(ports, ["0.0.0.0:8080->80/tcp", "443/tcp"], "the IPv6 twin is one port");
    }

    #[test]
    fn old_docker_lists_without_state_read_it_from_the_status() {
        let out = format!(r#"{{"ID":"{ID1}","Names":"/old","Image":"busybox","Status":"Up 2 minutes (Paused)"}}"#);
        let list = containers(&out).unwrap();
        assert_eq!(list[0].state, ContainerState::Paused);
        assert_eq!(list[0].name, "old");
    }

    #[test]
    fn podman_lists_are_one_array() {
        let out = format!(
            r#"[
  {{
    "AutoRemove": false,
    "Command": ["redis-server"],
    "Created": 1792454400,
    "CreatedAt": "",
    "Exited": false,
    "ExitCode": 0,
    "Id": "{ID1}",
    "Image": "docker.io/library/redis:7",
    "ImageID": "{IMG}",
    "Labels": {{"com.docker.compose.project": "cache"}},
    "Mounts": ["/data"],
    "Names": ["cache-redis-1"],
    "Networks": ["podman"],
    "Ports": [{{"host_ip": "", "container_port": 6379, "host_port": 6379, "range": 1, "protocol": "tcp"}}],
    "StartedAt": 1792458000,
    "State": "running",
    "Status": ""
  }},
  {{ "Id": "{ID2}", "Names": ["stopped"], "Image": "alpine", "State": "stopped", "ExitCode": 137, "Status": "" }}
]"#
        );
        let list = containers(&out).unwrap();
        let redis = &list[0];
        assert_eq!(redis.name, "cache-redis-1");
        assert_eq!(redis.command.as_deref(), Some("redis-server"));
        assert_eq!(redis.state, ContainerState::Running);
        assert_eq!(redis.status, "Running");
        assert_eq!(redis.created_at.as_deref(), Some("2026-10-20T00:00:00Z"));
        assert_eq!(redis.started_at.as_deref(), Some("2026-10-20T01:00:00Z"));
        assert_eq!(redis.ports[0].describe(), "6379->6379/tcp");
        assert_eq!(redis.project.as_deref(), Some("cache"));
        let stopped = &list[1];
        assert_eq!(stopped.state, ContainerState::Exited);
        assert_eq!(stopped.status, "Exited (137)");
        assert!(containers("[]").unwrap().is_empty());
        assert!(containers("").unwrap().is_empty());
    }

    #[test]
    fn hostile_entries_are_left_out_or_cleaned() {
        let out = concat!(
            r#"{"ID":"$(reboot)","Names":"x","Image":"y","State":"running"}"#,
            "\n",
            r#"{"ID":"1a2b3c4d5e6f1a2b3c4d5e6f","Names":"evil\u001b[31m; rm -rf /","Image":"y\u0007","State":"running"}"#,
        );
        let list = containers(out).unwrap();
        assert_eq!(list.len(), 1, "the entry without a hex id is gone");
        assert_eq!(list[0].name, "evil; rm -rf /", "shown as text, never run");
        assert_eq!(list[0].image, "y");
        assert!(containers("not json").is_err());
    }

    #[test]
    fn port_lists_take_ranges_and_bare_ports() {
        let ports = docker_ports("0.0.0.0:7000-7001->7000-7001/tcp, 127.0.0.1:53->53/udp, [::1]:9000->9000/tcp, 80");
        let shown: Vec<String> = ports.iter().map(PortMapping::describe).collect();
        assert_eq!(
            shown,
            [
                "0.0.0.0:7000->7000/tcp",
                "0.0.0.0:7001->7001/tcp",
                "127.0.0.1:53->53/udp",
                "[::1]:9000->9000/tcp",
                "80/tcp"
            ]
        );
    }

    #[test]
    fn stats_read_both_formats() {
        let docker = format!(
            r#"{{"BlockIO":"1.5MB / 0B","CPUPerc":"12.50%","Container":"{ID1}","ID":"{ID1}","MemPerc":"0.27%","MemUsage":"5.3MiB / 1.5GiB","Name":"web","NetIO":"1.2kB / 648B","PIDs":"3"}}"#
        );
        let s = &stats(&docker).unwrap()[0];
        assert_eq!(s.cpu_pct, Some(12.5));
        assert_eq!(s.mem_bytes, Some(5_557_453));
        assert_eq!(s.mem_limit_bytes, Some(1_610_612_736));
        assert_eq!(s.net_rx_bytes, Some(1200));
        assert_eq!(s.net_tx_bytes, Some(648));
        assert_eq!(s.block_read_bytes, Some(1_500_000));
        assert_eq!(s.pids, Some(3));
        let podman = format!(
            r#"[{{"id":"{}","name":"cache","cpu_percent":"0.15%","mem_usage":"4.1MB / 8.2GB","mem_percent":"0.05%","net_io":"--","block_io":"0B / 0B","pids":"4"}}]"#,
            &ID1[..12]
        );
        let s = &stats(&podman).unwrap()[0];
        assert_eq!(s.id.as_str(), &ID1[..12]);
        assert_eq!(s.cpu_pct, Some(0.15));
        assert_eq!(s.mem_bytes, Some(4_100_000));
        assert_eq!(s.net_rx_bytes, None);
    }

    #[test]
    fn docker_images_with_several_tags_are_one_image() {
        let out = format!(
            concat!(
                r#"{{"Containers":"N/A","CreatedAt":"2026-09-01 12:00:00 +0000 UTC","Digest":"<none>","ID":"sha256:{img}","Repository":"nginx","Size":"187MB","Tag":"1.27"}}"#,
                "\n",
                r#"{{"ID":"sha256:{img}","Repository":"nginx","Size":"187MB","Tag":"latest"}}"#,
                "\n",
                r#"{{"ID":"sha256:{other}","Repository":"<none>","Size":"12.5MB","Tag":"<none>"}}"#,
            ),
            img = IMG,
            other = ID2
        );
        let list = images(&out).unwrap();
        assert_eq!(list.len(), 2);
        let dangling = list.iter().find(|i| i.dangling).unwrap();
        assert!(dangling.tags.is_empty());
        assert_eq!(dangling.size_bytes, Some(12_500_000));
        let nginx = list.iter().find(|i| !i.dangling).unwrap();
        assert_eq!(nginx.tags, ["nginx:1.27", "nginx:latest"]);
        assert_eq!(nginx.containers, None);
        assert_eq!(nginx.created_at.as_deref(), Some("2026-09-01T12:00:00Z"));
    }

    #[test]
    fn podman_images_read_too() {
        let out = format!(
            r#"[{{"Id":"{IMG}","RepoTags":["docker.io/library/redis:7"],"Size":117000000,"Created":1790000000,"Containers":1,"Dangling":false}},
               {{"Id":"{ID2}","RepoTags":null,"Size":5000,"Dangling":true}}]"#
        );
        let list = images(&out).unwrap();
        let redis = list.iter().find(|i| !i.dangling).unwrap();
        assert_eq!(redis.tags, ["docker.io/library/redis:7"]);
        assert_eq!(redis.size_bytes, Some(117_000_000));
        assert_eq!(redis.containers, Some(1));
        assert!(list.iter().any(|i| i.dangling));
    }

    #[test]
    fn volumes_with_names_remotely_cant_pass_on_are_left_out() {
        let out = format!(
            concat!(
                r#"{{"Driver":"local","Labels":"com.docker.compose.project=shop","Mountpoint":"/var/lib/docker/volumes/pgdata/_data","Name":"pgdata","Scope":"local"}}"#,
                "\n",
                r#"{{"Driver":"local","Name":"{}"}}"#,
                "\n",
                r#"{{"Driver":"local","Name":"bad name; id"}}"#,
            ),
            ID1
        );
        let list = volumes(&out).unwrap();
        assert_eq!(list.len(), 2);
        assert_eq!(list[0].name.as_str(), "pgdata");
        assert_eq!(list[0].project.as_deref(), Some("shop"));
        assert!(list[1].anonymous);
        let podman = r#"[{"Name":"data","Driver":"local","Mountpoint":"/home/alice/.local/share/containers/storage/volumes/data/_data","CreatedAt":"2026-10-01T10:00:00Z","Labels":{},"Scope":"local"}]"#;
        assert_eq!(
            volumes(podman).unwrap()[0].created_at.as_deref(),
            Some("2026-10-01T10:00:00Z")
        );
    }

    #[test]
    fn networks_read_both_formats() {
        let docker = format!(
            r#"{{"CreatedAt":"2026-10-01 10:00:00.123456 +0000 UTC","Driver":"bridge","ID":"{ID1}","IPv6":"false","Internal":"false","Labels":"","Name":"bridge","Scope":"local"}}"#
        );
        let n = &networks(&docker).unwrap()[0];
        assert_eq!(n.name, "bridge");
        assert_eq!(n.internal, Some(false));
        assert_eq!(n.created_at.as_deref(), Some("2026-10-01T10:00:00Z"));
        let podman = format!(
            r#"[{{"name":"podman","id":"{ID2}","driver":"bridge","created":"2026-10-01T10:00:00Z","subnets":[{{"subnet":"10.88.0.0/16","gateway":"10.88.0.1"}}],"ipv6_enabled":false,"internal":false}}]"#
        );
        let n = &networks(&podman).unwrap()[0];
        assert_eq!(n.subnets, ["10.88.0.0/16"]);
        assert_eq!(n.ipv6, Some(false));
    }

    #[test]
    fn versions_read_with_or_without_a_server() {
        let docker = r#"{"Client":{"Version":"27.3.1","ApiVersion":"1.47","Os":"linux","Arch":"amd64"},"Server":{"Version":"27.3.1","ApiVersion":"1.47","Os":"linux","Arch":"amd64"}}"#;
        let v = version(docker).unwrap();
        assert_eq!(v.server.as_deref(), Some("27.3.1"));
        assert_eq!(v.platform.as_deref(), Some("linux/amd64"));
        let down = r#"{"Client":{"Version":"29.8.2","ApiVersion":"1.56","Os":"windows","Arch":"amd64"},"Server":null}"#;
        assert_eq!(version(down).unwrap().server, None);
        let podman = "{\n  \"Client\": {\n    \"APIVersion\": \"4.9.3\",\n    \"Version\": \"4.9.3\",\n    \"OsArch\": \"linux/amd64\"\n  }\n}\n";
        let v = version(podman).unwrap();
        assert_eq!(v.client.as_deref(), Some("4.9.3"));
        assert_eq!(v.api.as_deref(), Some("4.9.3"));
        assert_eq!(v.platform.as_deref(), Some("linux/amd64"));
    }

    #[test]
    fn details_name_env_variables_but_never_their_values() {
        let out = format!(
            r#"[{{
  "Id": "{ID1}",
  "Created": "2026-10-20T09:30:00.123456789Z",
  "Name": "/shop-web-1",
  "Image": "sha256:{IMG}",
  "RestartCount": 2,
  "Platform": "linux",
  "State": {{"Status": "running", "Running": true, "Paused": false, "OOMKilled": false, "ExitCode": 0, "Error": "",
             "StartedAt": "2026-10-20T09:30:01.5Z", "FinishedAt": "0001-01-01T00:00:00Z",
             "Health": {{"Status": "healthy", "FailingStreak": 0, "Log": [{{"Output": "ok"}}]}}}},
  "HostConfig": {{"RestartPolicy": {{"Name": "on-failure", "MaximumRetryCount": 3}}}},
  "Config": {{"Hostname": "4f1e", "User": "", "Env": ["PATH=/usr/bin", "DB_PASSWORD=hunter2", "TOKEN=abc=def"],
              "Cmd": ["nginx", "-g", "daemon off;"], "Image": "nginx:1.27", "WorkingDir": "/srv",
              "Entrypoint": ["/docker-entrypoint.sh"], "Labels": {{"com.docker.compose.project": "shop"}}}},
  "Mounts": [{{"Type": "volume", "Name": "shop_static", "Source": "/var/lib/docker/volumes/shop_static/_data", "Destination": "/srv", "RW": false}},
             {{"Type": "bind", "Source": "/etc/shop", "Destination": "/etc/nginx/conf.d", "RW": true}}],
  "NetworkSettings": {{"Ports": {{"80/tcp": [{{"HostIp": "0.0.0.0", "HostPort": "8080"}}], "443/tcp": null}},
                      "Networks": {{"shop_default": {{"IPAddress": "172.18.0.2", "Gateway": "172.18.0.1"}}}}}}
}}]"#
        );
        let d = details(&out).unwrap();
        assert_eq!(d.name, "shop-web-1");
        assert_eq!(d.image, "nginx:1.27");
        assert_eq!(d.state, ContainerState::Running);
        assert_eq!(d.env_names, ["PATH", "DB_PASSWORD", "TOKEN"]);
        let all = serde_json::to_string(&d).unwrap();
        assert!(!all.contains("hunter2") && !all.contains("abc=def"), "{all}");
        assert_eq!(d.restart_policy.as_deref(), Some("on-failure:3"));
        assert_eq!(d.restart_count, Some(2));
        assert_eq!(d.health.as_ref().map(|h| h.status.as_str()), Some("healthy"));
        assert_eq!(d.started_at.as_deref(), Some("2026-10-20T09:30:01.5Z"));
        assert_eq!(d.finished_at, None, "year 1 means never");
        assert_eq!(d.command.as_deref(), Some("nginx -g daemon off;"));
        assert_eq!(d.mounts.len(), 2);
        assert!(d.mounts[0].read_only);
        assert_eq!(d.mounts[0].name.as_deref(), Some("shop_static"));
        assert_eq!(d.networks[0].ip_address.as_deref(), Some("172.18.0.2"));
        let ports: Vec<String> = d.ports.iter().map(PortMapping::describe).collect();
        assert_eq!(ports, ["0.0.0.0:8080->80/tcp", "443/tcp"]);
        assert_eq!(d.project.as_deref(), Some("shop"));
    }

    #[test]
    fn logs_merge_both_streams_by_time_and_follow_after_a_time() {
        let stdout =
            "2026-10-21T10:00:00.000000001Z GET /\n2026-10-21T10:00:02.000000000Z \x1b[32mGET /health\x1b[0m\r\n";
        let stderr = "2026-10-21T10:00:01.000000000Z warn: slow\n";
        let lines = logs(stdout, stderr, None);
        let texts: Vec<&str> = lines.iter().map(|l| l.text.as_str()).collect();
        assert_eq!(texts, ["GET /", "warn: slow", "GET /health"]);
        assert_eq!(lines[1].stream, LogStream::Stderr);
        let after = logs(stdout, stderr, Some("2026-10-21T10:00:01.000000000Z"));
        assert_eq!(after.len(), 1);
        assert_eq!(after[0].text, "GET /health");
        let plain = logs("no time here\n", "", None);
        assert_eq!(plain[0].at, None);
    }

    #[test]
    fn sizes_take_decimal_and_binary_units() {
        assert_eq!(size_bytes("0B"), Some(0));
        assert_eq!(size_bytes("1.5kB"), Some(1500));
        assert_eq!(size_bytes("2KiB"), Some(2048));
        assert_eq!(size_bytes("1GB"), Some(1_000_000_000));
        assert_eq!(size_bytes("N/A"), None);
        assert_eq!(size_bytes("12 parsecs"), None);
    }

    #[test]
    fn prunes_say_what_they_freed() {
        assert_eq!(
            prune_note("Deleted Containers:\nabc\n\nTotal reclaimed space: 1.2GB\n").as_deref(),
            Some("reclaimed 1.2GB")
        );
        assert_eq!(prune_note("abc\ndef\n").as_deref(), Some("removed 2"));
        assert_eq!(prune_note("").as_deref(), Some("nothing to remove"));
    }
}
