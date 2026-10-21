//! CT-01: the test server's `docker` and `podman` programs. They answer the commands Remotely sends
//! from a [`Fixture`], in each CLI's own JSON (`--format '{{json .}}'` lines for Docker, a `--format
//! json` array for Podman), and change it the way the CLIs would. Docker refuses a user outside the
//! `docker` group (like the daemon's socket) unless the command runs as root; Podman runs rootless.

use serde_json::{json, Value};
use time::OffsetDateTime;

use crate::adapters::containers::{ContainerState, LogStream, PortMapping, PruneWhat};
use crate::fakes::containers::{rfc3339, FakeChange, FakeContainer, Fixture};

/// What one run printed.
pub struct Ran {
    pub stdout: String,
    pub stderr: String,
    pub status: u32,
}

fn ok(stdout: String) -> Ran {
    Ran {
        stdout,
        stderr: String::new(),
        status: 0,
    }
}

fn fail(stderr: impl Into<String>, status: u32) -> Ran {
    let mut stderr = stderr.into();
    if !stderr.ends_with('\n') {
        stderr.push('\n');
    }
    Ran {
        stdout: String::new(),
        stderr,
        status,
    }
}

/// Docker's `2026-10-21 09:30:00 +0000 UTC`.
fn docker_time(unix: i64) -> String {
    OffsetDateTime::from_unix_timestamp(unix)
        .ok()
        .map(|t| {
            format!(
                "{:04}-{:02}-{:02} {:02}:{:02}:{:02} +0000 UTC",
                t.year(),
                u8::from(t.month()),
                t.day(),
                t.hour(),
                t.minute(),
                t.second()
            )
        })
        .unwrap_or_default()
}

/// RFC 3339 with nanoseconds, as `logs --timestamps` prints it.
fn log_time(unix: i64, n: usize) -> String {
    let base = rfc3339(unix);
    let secs = base.trim_end_matches('Z');
    format!("{secs}.{n:09}Z")
}

fn docker_ports(ports: &[PortMapping]) -> String {
    let mut out = Vec::new();
    for p in ports {
        match (&p.host_ip, p.host_port) {
            (Some(ip), Some(host)) => {
                out.push(format!("{ip}:{host}->{}/{}", p.container_port, p.protocol));
                if ip == "0.0.0.0" {
                    out.push(format!(":::{host}->{}/{}", p.container_port, p.protocol));
                }
            }
            _ => out.push(format!("{}/{}", p.container_port, p.protocol)),
        }
    }
    out.join(", ")
}

/// Podman's full image names: `docker.io/library/nginx:1.27`, a registry's own names as they are.
fn podman_name(image: &str) -> String {
    match image.split_once('/') {
        Some((first, _)) if first.contains('.') || first.contains(':') || first == "localhost" => image.to_owned(),
        Some(_) => format!("docker.io/{image}"),
        None => format!("docker.io/library/{image}"),
    }
}

fn podman_state(state: ContainerState) -> &'static str {
    match state {
        ContainerState::Exited => "exited",
        other => other.as_str(),
    }
}

fn lines(values: impl Iterator<Item = Value>) -> String {
    values.map(|v| format!("{v}\n")).collect()
}

/// Runs `program args`. `docker_access`: the user may reach the Docker daemon (root, or the group).
pub fn run(fixture: &mut Fixture, program: &str, args: &[String], docker_access: bool) -> Ran {
    let podman = program == "podman";
    if !podman && !docker_access {
        return fail(
            "permission denied while trying to connect to the Docker daemon socket at unix:///var/run/docker.sock: Get \"http://%2Fvar%2Frun%2Fdocker.sock/v1.47/containers/json\": dial unix /var/run/docker.sock: connect: permission denied",
            1,
        );
    }
    let words: Vec<&str> = args.iter().map(String::as_str).collect();
    let json = |rest: &[&str]| rest.windows(2).any(|w| w[0] == "--format");
    match words.as_slice() {
        ["version", rest @ ..] if json(rest) => {
            if podman {
                ok(format!(
                    "{{\n  \"Client\": {{\n    \"APIVersion\": \"{v}\",\n    \"Version\": \"{v}\",\n    \"OsArch\": \"linux/amd64\"\n  }}\n}}\n",
                    v = "4.9.3"
                ))
            } else {
                let v = &fixture.version;
                ok(format!(
                    "{}\n",
                    json!({
                        "Client": {"Version": v, "ApiVersion": "1.47", "Os": "linux", "Arch": "amd64"},
                        "Server": {"Version": v, "ApiVersion": "1.47", "Os": "linux", "Arch": "amd64"}
                    })
                ))
            }
        }
        ["ps", "-a", "--no-trunc", rest @ ..] if json(rest) => {
            let mut list: Vec<&FakeContainer> = fixture.containers.iter().collect();
            list.sort_by_key(|c| std::cmp::Reverse(c.created));
            if podman {
                let items: Vec<Value> = list.iter().map(|c| podman_ps(c)).collect();
                ok(format!("{}\n", Value::Array(items)))
            } else {
                ok(lines(list.iter().map(|c| docker_ps(c))))
            }
        }
        ["stats", "--no-stream", rest @ ..] => {
            let running = fixture.containers.iter().filter(|c| c.state.is_up());
            if podman {
                let items: Vec<Value> = running
                    .map(|c| {
                        json!({
                            "id": c.short_id(), "name": c.name,
                            "cpu_percent": format!("{:.2}%", c.cpu_pct),
                            "mem_usage": format!("{:.1}MB / 2.1GB", c.mem_bytes as f64 / 1e6),
                            "mem_percent": format!("{:.2}%", c.mem_bytes as f64 / 2.1e9 * 100.0),
                            "net_io": "1.2kB / 648B", "block_io": "0B / 0B", "pids": "2"
                        })
                    })
                    .collect();
                ok(format!("{}\n", Value::Array(items)))
            } else if rest.contains(&"--no-trunc") {
                ok(lines(running.map(|c| {
                    json!({
                        "BlockIO": "0B / 0B", "CPUPerc": format!("{:.2}%", c.cpu_pct), "Container": c.id, "ID": c.id,
                        "MemPerc": format!("{:.2}%", c.mem_bytes as f64 / 2_147_483_648.0 * 100.0),
                        "MemUsage": format!("{:.1}MiB / 2GiB", c.mem_bytes as f64 / 1_048_576.0),
                        "Name": c.name, "NetIO": "1.2kB / 648B", "PIDs": "2"
                    })
                })))
            } else {
                fail("unexpected stats arguments", 125)
            }
        }
        ["inspect", "--type", "container", id] => match fixture.containers.iter().find(|c| c.id.starts_with(id)) {
            Some(c) => ok(format!("{:#}\n", Value::Array(vec![inspect(c, podman)]))),
            None if podman => fail(format!("Error: no such object: \"{id}\""), 125),
            None => fail(format!("Error: No such container: {id}"), 1),
        },
        ["logs", "--timestamps", "--tail", tail, rest @ ..] => {
            let (since, id) = match rest {
                ["--since", since, id] => (Some(*since), *id),
                [id] => (None, *id),
                _ => return fail("unexpected logs arguments", 125),
            };
            let tail: usize = tail.parse().unwrap_or(100);
            let Some(c) = fixture.containers.iter_mut().find(|c| c.id.starts_with(id)) else {
                return fail(format!("Error response from daemon: No such container: {id}"), 1);
            };
            if c.live_logs && c.state == ContainerState::Running {
                let now = OffsetDateTime::now_utc().unix_timestamp();
                c.logs.push((
                    now,
                    LogStream::Stdout,
                    "192.0.2.20 - - \"GET /health HTTP/1.1\" 200 2".into(),
                ));
            }
            let all: Vec<(String, LogStream, &str)> = c
                .logs
                .iter()
                .enumerate()
                .map(|(n, (at, stream, text))| (log_time(*at, n), *stream, text.as_str()))
                .filter(|(at, _, _)| since.is_none_or(|s| at.as_str() > s))
                .collect();
            let start = all.len().saturating_sub(tail);
            let mut out = Ran {
                stdout: String::new(),
                stderr: String::new(),
                status: 0,
            };
            for (at, stream, text) in &all[start..] {
                let line = format!("{at} {text}\n");
                match stream {
                    LogStream::Stdout => out.stdout.push_str(&line),
                    LogStream::Stderr => out.stderr.push_str(&line),
                }
            }
            out
        }
        ["images", "--no-trunc", rest @ ..] if json(rest) => {
            if podman {
                let items: Vec<Value> = fixture
                    .images
                    .iter()
                    .map(|i| {
                        let used = fixture.containers.iter().filter(|c| i.tags.contains(&c.image)).count();

                        json!({
                            "Id": i.id,
                            "RepoTags": if i.tags.is_empty() { Value::Null } else { json!(i.tags.iter().map(|t| podman_name(t)).collect::<Vec<_>>()) },
                            "Size": i.size, "Created": i.created, "Containers": used, "Dangling": i.tags.is_empty()
                        })
                    })
                    .collect();
                ok(format!("{}\n", Value::Array(items)))
            } else {
                let mut out = String::new();
                for i in &fixture.images {
                    let rows: Vec<(String, String)> = if i.tags.is_empty() {
                        vec![("<none>".into(), "<none>".into())]
                    } else {
                        i.tags
                            .iter()
                            .map(|t| match t.rsplit_once(':') {
                                Some((repo, tag)) if !tag.contains('/') => (repo.to_owned(), tag.to_owned()),
                                _ => (t.clone(), "latest".to_owned()),
                            })
                            .collect()
                    };
                    for (repo, tag) in rows {
                        let row = json!({
                            "Containers": "N/A", "CreatedAt": docker_time(i.created), "CreatedSince": "3 weeks ago",
                            "Digest": "<none>", "ID": format!("sha256:{}", i.id), "Repository": repo,
                            "SharedSize": "N/A", "Size": format!("{}MB", i.size / 1_000_000), "Tag": tag,
                            "UniqueSize": "N/A", "VirtualSize": format!("{}MB", i.size / 1_000_000)
                        });
                        out.push_str(&format!("{row}\n"));
                    }
                }
                ok(out)
            }
        }
        ["volume", "ls", rest @ ..] if json(rest) => {
            if podman {
                let items: Vec<Value> = fixture
                    .volumes
                    .iter()
                    .map(|v| {
                        let labels = match &v.project {
                            Some(p) => json!({"com.docker.compose.project": p}),
                            None => json!({}),
                        };
                        json!({
                            "Name": v.name, "Driver": v.driver, "Scope": "local", "Labels": labels,
                            "Mountpoint": format!("/home/alice/.local/share/containers/storage/volumes/{}/_data", v.name),
                            "CreatedAt": "2026-10-01T10:00:00Z"
                        })
                    })
                    .collect();
                ok(format!("{}\n", Value::Array(items)))
            } else {
                ok(lines(fixture.volumes.iter().map(|v| {
                    json!({
                        "Availability": "N/A", "Driver": v.driver, "Group": "N/A",
                        "Labels": v.project.as_ref().map(|p| format!("com.docker.compose.project={p}")).unwrap_or_default(),
                        "Links": "N/A", "Mountpoint": format!("/var/lib/docker/volumes/{}/_data", v.name),
                        "Name": v.name, "Scope": "local", "Size": "N/A", "Status": "N/A"
                    })
                })))
            }
        }
        ["network", "ls", "--no-trunc", rest @ ..] if json(rest) => {
            if podman {
                let items: Vec<Value> = fixture
                    .networks
                    .iter()
                    .map(|n| {
                        json!({
                            "name": n.name, "id": n.id, "driver": n.driver, "created": "2026-10-01T10:00:00Z",
                            "subnets": n.subnet.iter().map(|s| json!({"subnet": s})).collect::<Vec<_>>(),
                            "ipv6_enabled": false, "internal": false
                        })
                    })
                    .collect();
                ok(format!("{}\n", Value::Array(items)))
            } else {
                ok(lines(fixture.networks.iter().map(|n| {
                    json!({
                        "CreatedAt": "2026-10-01 10:00:00.123456789 +0000 UTC", "Driver": n.driver, "ID": n.id,
                        "IPv6": "false", "Internal": "false", "Labels": "", "Name": n.name, "Scope": "local"
                    })
                })))
            }
        }
        [verb @ ("start" | "stop" | "restart" | "pause" | "unpause"), id] => {
            let id = (*id).to_owned();
            let change = match *verb {
                "start" => FakeChange::Start(id),
                "stop" => FakeChange::Stop(id),
                "restart" => FakeChange::Restart(id),
                "pause" => FakeChange::Pause(id),
                _ => FakeChange::Unpause(id),
            };
            applied(fixture, &change)
        }
        ["rm", "-f", id] => applied(
            fixture,
            &FakeChange::Remove {
                id: (*id).to_owned(),
                force: true,
            },
        ),
        ["rm", id] => applied(
            fixture,
            &FakeChange::Remove {
                id: (*id).to_owned(),
                force: false,
            },
        ),
        ["rmi", id] => applied(fixture, &FakeChange::RemoveImage((*id).to_owned())),
        ["volume", "rm", name] => applied(fixture, &FakeChange::RemoveVolume((*name).to_owned())),
        ["pull", "-q", reference] => applied(fixture, &FakeChange::Pull((*reference).to_owned())),
        ["container", "prune", "-f"] => applied(fixture, &FakeChange::Prune(PruneWhat::Containers)),
        ["image", "prune", "-f"] => applied(fixture, &FakeChange::Prune(PruneWhat::Images)),
        ["volume", "prune", "-f"] => applied(fixture, &FakeChange::Prune(PruneWhat::Volumes)),
        ["builder", "prune", "-f"] if !podman => ok("Total reclaimed space: 0B\n".into()),
        _ => fail(
            format!(
                "{program}: '{}' is not a command this test {program} knows",
                words.join(" ")
            ),
            125,
        ),
    }
}

fn applied(fixture: &mut Fixture, change: &FakeChange) -> Ran {
    match fixture.apply(change) {
        Ok(stdout) => ok(stdout),
        Err(stderr) => fail(stderr, 1),
    }
}

fn docker_ps(c: &FakeContainer) -> Value {
    let quoted = format!("\"{}\"", c.command.join(" "));
    json!({
        "Command": quoted,
        "CreatedAt": docker_time(c.created),
        "ID": c.id,
        "Image": c.image,
        "Labels": c.project.as_ref().map(|p| format!("com.docker.compose.project={p},com.docker.compose.service={}", c.name)).unwrap_or_default(),
        "LocalVolumes": c.mounts.iter().filter(|m| m.volume.is_some()).count().to_string(),
        "Mounts": c.mounts.iter().map(|m| m.volume.clone().unwrap_or_else(|| m.source.clone())).collect::<Vec<_>>().join(","),
        "Names": c.name,
        "Networks": c.networks.join(","),
        "Ports": docker_ports(&c.ports),
        "RunningFor": "30 hours ago",
        "Size": "0B",
        "State": c.state.as_str(),
        "Status": c.status(),
    })
}

fn podman_ps(c: &FakeContainer) -> Value {
    let ports: Vec<Value> = c
        .ports
        .iter()
        .map(|p| {
            json!({
                "host_ip": p.host_ip.clone().filter(|ip| ip != "0.0.0.0").unwrap_or_default(),
                "container_port": p.container_port, "host_port": p.host_port, "range": 1, "protocol": p.protocol
            })
        })
        .collect();
    let labels = match &c.project {
        Some(p) => json!({"com.docker.compose.project": p}),
        None => Value::Null,
    };
    json!({
        "AutoRemove": false,
        "Command": c.command,
        "Created": c.created,
        "CreatedAt": "",
        "Exited": c.state == ContainerState::Exited,
        "ExitCode": c.exit_code,
        "Id": c.id,
        "Image": podman_name(&c.image),
        "ImageID": c.image_id,
        "Labels": labels,
        "Mounts": c.mounts.iter().map(|m| m.destination.clone()).collect::<Vec<_>>(),
        "Names": [c.name],
        "Networks": c.networks,
        "Ports": if ports.is_empty() { Value::Null } else { Value::Array(ports) },
        "StartedAt": c.started.unwrap_or(0),
        "State": podman_state(c.state),
        "Status": "",
    })
}

fn inspect(c: &FakeContainer, podman: bool) -> Value {
    let mut ports = serde_json::Map::new();
    for p in &c.ports {
        ports.insert(
            format!("{}/{}", p.container_port, p.protocol),
            json!([{"HostIp": p.host_ip, "HostPort": p.host_port.map(|h| h.to_string())}]),
        );
    }
    let networks: serde_json::Map<String, Value> = c
        .networks
        .iter()
        .enumerate()
        .map(|(i, n)| {
            let ip = if c.state.is_up() {
                format!("172.18.0.{}", i + 2)
            } else {
                String::new()
            };
            (n.clone(), json!({"IPAddress": ip, "Gateway": "172.18.0.1"}))
        })
        .collect();
    let health = c
        .health
        .as_ref()
        .map(|h| json!({"Status": h, "FailingStreak": 0, "Log": [{"Output": "ok"}]}));
    let mut state = json!({
        "Status": if podman { podman_state(c.state) } else { c.state.as_str() },
        "Running": c.state.is_up(),
        "Paused": c.state == ContainerState::Paused,
        "OOMKilled": false,
        "ExitCode": c.exit_code,
        "Error": "",
        "StartedAt": c.started.map(rfc3339).unwrap_or_else(|| "0001-01-01T00:00:00Z".into()),
        "FinishedAt": "0001-01-01T00:00:00Z",
    });
    if let (Some(health), Some(map)) = (health, state.as_object_mut()) {
        map.insert(if podman { "Healthcheck" } else { "Health" }.into(), health);
    }
    let labels = match &c.project {
        Some(p) => json!({"com.docker.compose.project": p}),
        None => json!({}),
    };
    json!({
        "Id": c.id,
        "Created": rfc3339(c.created),
        "Name": if podman { c.name.clone() } else { format!("/{}", c.name) },
        "Image": format!("sha256:{}", c.image_id),
        "RestartCount": 0,
        "Platform": "linux",
        "State": state,
        "HostConfig": {"RestartPolicy": {"Name": c.restart_policy, "MaximumRetryCount": 0}},
        "Config": {
            "Hostname": c.short_id(), "User": "", "Env": c.env, "Cmd": c.command, "Image": c.image,
            "WorkingDir": "", "Entrypoint": Value::Null, "Labels": labels
        },
        "Mounts": c.mounts.iter().map(|m| json!({
            "Type": if m.volume.is_some() { "volume" } else { "bind" }, "Name": m.volume, "Source": m.source,
            "Destination": m.destination, "RW": !m.read_only
        })).collect::<Vec<_>>(),
        "NetworkSettings": {"Ports": ports, "Networks": networks},
    })
}
