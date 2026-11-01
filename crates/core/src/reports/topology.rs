//! FD-08: the QL-21 topology map as an SVG for the handover pack, made here from the stored data, never taken from
//! the window: this PC, the networks the VMs' adapters are on, the VMs, and the saved sessions that reach them with
//! the jump hosts on the way. The graph and the layered layout follow the Map's (`src/lib/topology.ts` and
//! `topology-layout.ts`): the same network keys and labels, columns by layer, a lane for an edge that crosses a column,
//! barycentre sweeps, then each item level with its neighbours. Open tunnels are left out: they are this PC's, now.
//!
//! The SVG holds rectangles, paths and text only (no script, no link, no image, no style sheet, no outside
//! reference), every label escaped and cut by character, and the pack embeds it as an `<img>`, where nothing in an SVG
//! could run anyway.

use std::collections::{HashMap, HashSet};

use uuid::Uuid;

use super::html::escape;
use super::table::clean;
use crate::adapters::hypervisor::Hypervisor;
use crate::adapters::vm_hardware::VirtualNic;
use crate::domain::PowerState;
use crate::sessions::SessionRecord;
use crate::store::VmRecord;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeKind {
    Pc,
    Network,
    Vm,
    Session,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Node {
    pub id: String,
    pub kind: NodeKind,
    pub label: String,
    pub sub: String,
    /// A VM's power: running, off, paused or suspended.
    pub on: Option<bool>,
    pub layer: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Edge {
    pub from: String,
    pub to: String,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct Graph {
    pub nodes: Vec<Node>,
    pub edges: Vec<Edge>,
}

/// A VM's adapters as read before (QL-21's `vm_networks` without a fresh read).
pub struct VmNics<'a> {
    pub vmx_path: &'a str,
    pub hypervisor: Hypervisor,
    pub nics: &'a [VirtualNic],
}

const PC_ID: &str = "pc";

/// The network an adapter is on, as a key and a name (the Map's `networkKey`); `None` for an adapter on none.
pub fn network_key(hypervisor: Hypervisor, nic: &VirtualNic) -> Option<(String, String, String)> {
    let connection = nic.connection.as_deref().unwrap_or("").to_lowercase();
    let name = nic
        .network_name
        .as_deref()
        .map(str::trim)
        .filter(|n| !n.is_empty())
        .map(str::to_owned);
    if hypervisor == Hypervisor::Vmware {
        let vnet = match connection.as_str() {
            "nat" => Some("vmnet8".to_owned()),
            "hostonly" => Some("vmnet1".to_owned()),
            "bridged" => Some("vmnet0".to_owned()),
            _ => match name.as_deref().map(str::to_lowercase) {
                Some(n) if n.starts_with("vmnet") => Some(n),
                _ => connection
                    .split_once("(vmnet")
                    .and_then(|(_, rest)| rest.split_once(')'))
                    .map(|(digits, _)| format!("vmnet{digits}"))
                    .filter(|v| {
                        v.strip_prefix("vmnet")
                            .is_some_and(|d| !d.is_empty() && d.chars().all(|c| c.is_ascii_digit()))
                    }),
            },
        };
        if let Some(vnet) = vnet {
            let label = match vnet.as_str() {
                "vmnet0" => "Bridged (VMnet0)".to_owned(),
                "vmnet1" => "Host-only (VMnet1)".to_owned(),
                "vmnet8" => "NAT (VMnet8)".to_owned(),
                other => format!("VMnet{}", other.strip_prefix("vmnet").unwrap_or(other)),
            };
            return Some((format!("vmware:{vnet}"), label, "Workstation".to_owned()));
        }
        if connection.is_empty() {
            return None;
        }
        return Some((format!("vmware:{connection}"), connection, "Workstation".to_owned()));
    }
    let named = name.clone().unwrap_or_default();
    let vbox = "VirtualBox".to_owned();
    match connection.as_str() {
        "" | "none" | "null" => None,
        "nat" => Some((
            "virtualbox:nat".into(),
            "NAT".into(),
            "VirtualBox: each VM its own".into(),
        )),
        "bridged" => Some((
            format!("virtualbox:bridged:{named}"),
            name.map_or_else(|| "Bridged".to_owned(), |n| format!("Bridged: {n}")),
            vbox,
        )),
        "hostonly" => Some((
            format!("virtualbox:hostonly:{named}"),
            name.map_or_else(|| "Host-only".to_owned(), |n| format!("Host-only: {n}")),
            vbox,
        )),
        "natnetwork" => Some((
            format!("virtualbox:natnetwork:{named}"),
            format!("NAT network: {}", name.as_deref().unwrap_or("?")),
            vbox,
        )),
        "intnet" => Some((
            format!("virtualbox:intnet:{named}"),
            format!("Internal: {}", name.as_deref().unwrap_or("?")),
            vbox,
        )),
        other => Some((
            format!("virtualbox:{other}:{named}"),
            name.unwrap_or_else(|| other.to_owned()),
            vbox,
        )),
    }
}

/// The diagram's nodes and edges: every VM (off ones too, since a handover lists them all), the networks they are
/// on, the sessions that reach a VM, jump hosts and the sessions behind them.
pub fn build(vms: &[VmRecord], nics: &[VmNics<'_>], sessions: &[SessionRecord]) -> Graph {
    let mut graph = Graph::default();
    let mut ids: HashSet<String> = HashSet::new();
    let mut add = |graph: &mut Graph, node: Node| {
        if ids.insert(node.id.clone()) {
            graph.nodes.push(node);
        }
    };
    add(
        &mut graph,
        Node {
            id: PC_ID.into(),
            kind: NodeKind::Pc,
            label: "This PC".into(),
            sub: "Workstation and VirtualBox host".into(),
            on: None,
            layer: 0,
        },
    );
    let by_path: HashMap<&str, &VmNics<'_>> = nics.iter().map(|n| (n.vmx_path, n)).collect();
    let mut edges: Vec<Edge> = Vec::new();
    for vm in vms {
        let vm_id = format!("vm:{}", vm.id);
        add(
            &mut graph,
            Node {
                id: vm_id.clone(),
                kind: NodeKind::Vm,
                label: vm.display_name.clone(),
                sub: vm.ip_address.clone().unwrap_or_else(|| {
                    match vm.hypervisor {
                        Hypervisor::VirtualBox => "VirtualBox",
                        Hypervisor::Vmware => "Workstation",
                    }
                    .to_owned()
                }),
                on: Some(vm.power_state == PowerState::Running),
                layer: 2,
            },
        );
        for nic in by_path.get(vm.vmx_path.as_str()).map(|n| n.nics).unwrap_or(&[]) {
            let Some((key, label, sub)) = network_key(vm.hypervisor, nic) else {
                continue;
            };
            let net_id = format!("net:{key}");
            add(
                &mut graph,
                Node {
                    id: net_id.clone(),
                    kind: NodeKind::Network,
                    label,
                    sub,
                    on: None,
                    layer: 1,
                },
            );
            edges.push(Edge {
                from: net_id,
                to: vm_id.clone(),
            });
        }
    }
    let networks: Vec<String> = graph
        .nodes
        .iter()
        .filter(|n| n.kind == NodeKind::Network)
        .map(|n| n.id.clone())
        .collect();
    for net in networks {
        edges.insert(
            0,
            Edge {
                from: PC_ID.into(),
                to: net,
            },
        );
    }

    let by_id: HashMap<Uuid, &SessionRecord> = sessions.iter().map(|s| (s.id, s)).collect();
    let vm_ids: HashSet<&str> = vms.iter().map(|v| v.id.as_str()).collect();
    let jump_hosts: HashSet<Uuid> = sessions
        .iter()
        .filter_map(|s| s.jump_session_id.filter(|j| by_id.contains_key(j)))
        .collect();
    let mut wanted: Vec<Uuid> = Vec::new();
    let mut wanted_set: HashSet<Uuid> = HashSet::new();
    for s in sessions {
        let linked = s.vm_id.as_deref().is_some_and(|v| vm_ids.contains(v));
        if linked || jump_hosts.contains(&s.id) || s.jump_session_id.is_some() {
            let mut next = Some(s.id);
            let mut seen = HashSet::new();
            while let Some(id) = next.filter(|id| by_id.contains_key(id) && seen.insert(*id)) {
                if wanted_set.insert(id) {
                    wanted.push(id);
                }
                next = by_id.get(&id).and_then(|s| s.jump_session_id);
            }
        }
    }
    let mut layers: HashMap<Uuid, u32> = HashMap::new();
    for id in &wanted {
        let layer = session_layer(*id, &by_id, &wanted_set, &mut layers, &mut HashSet::new());
        let Some(s) = by_id.get(id) else { continue };
        add(
            &mut graph,
            Node {
                id: format!("session:{id}"),
                kind: NodeKind::Session,
                label: s.name.clone(),
                sub: match &s.username {
                    Some(user) => format!("{user}@{}", s.host),
                    None => s.host.clone(),
                },
                on: None,
                layer,
            },
        );
    }
    for id in &wanted {
        let Some(s) = by_id.get(id) else { continue };
        if let Some(vm) = s.vm_id.as_deref().filter(|v| vm_ids.contains(v)) {
            edges.push(Edge {
                from: format!("vm:{vm}"),
                to: format!("session:{id}"),
            });
        }
        if let Some(jump) = s.jump_session_id.filter(|j| wanted_set.contains(j)) {
            edges.push(Edge {
                from: format!("session:{jump}"),
                to: format!("session:{id}"),
            });
        }
    }
    let mut seen = HashSet::new();
    graph.edges = edges
        .into_iter()
        .filter(|e| ids.contains(&e.from) && ids.contains(&e.to) && seen.insert((e.from.clone(), e.to.clone())))
        .collect();
    graph
}

/// A session's column: after its jump host's, and never before the sessions' first (3).
fn session_layer(
    id: Uuid,
    by_id: &HashMap<Uuid, &SessionRecord>,
    wanted: &HashSet<Uuid>,
    layers: &mut HashMap<Uuid, u32>,
    seen: &mut HashSet<Uuid>,
) -> u32 {
    if let Some(layer) = layers.get(&id) {
        return *layer;
    }
    if !seen.insert(id) {
        return 3;
    }
    let mut layer = 3;
    if let Some(jump) = by_id
        .get(&id)
        .and_then(|s| s.jump_session_id)
        .filter(|j| wanted.contains(j))
    {
        layer = layer.max(session_layer(jump, by_id, wanted, layers, seen) + 1);
    }
    layers.insert(id, layer);
    layer
}

// ---- Layout ----

const NODE_W: f64 = 200.0;
const NODE_H: f64 = 52.0;
const GAP_X: f64 = 72.0;
const GAP_Y: f64 = 14.0;
const LANE_H: f64 = 6.0;
const SWEEPS: usize = 4;
/// Nodes drawn at most: past that a diagram can't be read, and the inventory's tables list everything.
pub const MAX_NODES: usize = 400;

struct Item {
    id: String,
    column: usize,
    lane: bool,
}

/// Where each node goes, and each edge's path.
pub struct Layout {
    pub nodes: Vec<(usize, f64, f64)>,
    pub paths: Vec<String>,
    pub width: f64,
    pub height: f64,
}

fn mean(values: &[f64]) -> Option<f64> {
    if values.is_empty() {
        None
    } else {
        Some(values.iter().sum::<f64>() / values.len() as f64)
    }
}

fn r(n: f64) -> String {
    let v = (n * 10.0).round() / 10.0;
    if v.fract() == 0.0 {
        format!("{v:.0}")
    } else {
        format!("{v:.1}")
    }
}

fn curve(x1: f64, y1: f64, x2: f64, y2: f64) -> String {
    let bend = (GAP_X / 2.0).max((x2 - x1).abs() / 2.0);
    format!(
        "C {} {}, {} {}, {} {}",
        r(x1 + bend),
        r(y1),
        r(x2 - bend),
        r(y2),
        r(x2),
        r(y2)
    )
}

/// The Map's layered layout (`layoutTopology`), for the graph's nodes in its order.
pub fn layout(graph: &Graph) -> Layout {
    let layers: Vec<u32> = {
        let mut l: Vec<u32> = graph.nodes.iter().map(|n| n.layer).collect();
        l.sort_unstable();
        l.dedup();
        l
    };
    let column_of_layer: HashMap<u32, usize> = layers.iter().enumerate().map(|(i, l)| (*l, i)).collect();
    let mut items: Vec<Item> = graph
        .nodes
        .iter()
        .map(|n| Item {
            id: n.id.clone(),
            column: column_of_layer.get(&n.layer).copied().unwrap_or(0),
            lane: false,
        })
        .collect();
    let mut column: HashMap<String, usize> = items.iter().map(|i| (i.id.clone(), i.column)).collect();
    let mut links: Vec<(String, String)> = Vec::new();
    let mut chains: Vec<Vec<String>> = Vec::new();
    for (n, e) in graph.edges.iter().enumerate() {
        let (Some(&a), Some(&b)) = (column.get(&e.from), column.get(&e.to)) else {
            chains.push(Vec::new());
            continue;
        };
        let mut way = vec![e.from.clone()];
        for c in (a + 1)..b {
            let id = format!("~{n}:{c}");
            items.push(Item {
                id: id.clone(),
                column: c,
                lane: true,
            });
            way.push(id);
        }
        way.push(e.to.clone());
        for k in 1..way.len() {
            links.push((way[k - 1].clone(), way[k].clone()));
        }
        chains.push(way);
    }
    for item in &items {
        column.insert(item.id.clone(), item.column);
    }
    let count = items.iter().map(|i| i.column).max().map_or(0, |m| m + 1);
    let labels: HashMap<&str, &Node> = graph.nodes.iter().map(|n| (n.id.as_str(), n)).collect();
    let mut columns: Vec<Vec<String>> = vec![Vec::new(); count];
    // Networks by name first, the rest as given.
    let mut start: Vec<&Item> = items.iter().collect();
    start.sort_by(|a, b| match (labels.get(a.id.as_str()), labels.get(b.id.as_str())) {
        (Some(x), Some(y)) if x.kind == NodeKind::Network && y.kind == NodeKind::Network => x.label.cmp(&y.label),
        _ => std::cmp::Ordering::Equal,
    });
    for item in start {
        columns[item.column].push(item.id.clone());
    }
    let mut neighbours: HashMap<String, Vec<String>> = items.iter().map(|i| (i.id.clone(), Vec::new())).collect();
    for (from, to) in &links {
        neighbours.entry(from.clone()).or_default().push(to.clone());
        neighbours.entry(to.clone()).or_default().push(from.clone());
    }
    let position = |columns: &[Vec<String>]| -> HashMap<String, f64> {
        let mut at = HashMap::new();
        for ids in columns {
            for (i, id) in ids.iter().enumerate() {
                at.insert(id.clone(), i as f64);
            }
        }
        at
    };
    let reorder = |columns: &mut Vec<Vec<String>>, c: usize, left: bool| {
        let at = position(columns);
        let mut keyed: Vec<(f64, usize, String)> = columns[c]
            .iter()
            .enumerate()
            .map(|(i, id)| {
                let near: Vec<f64> = neighbours
                    .get(id)
                    .map(|n| {
                        n.iter()
                            .filter(|o| {
                                let oc = column.get(*o).copied().unwrap_or(0);
                                if left {
                                    oc < c
                                } else {
                                    oc > c
                                }
                            })
                            .map(|o| at.get(o).copied().unwrap_or(0.0))
                            .collect()
                    })
                    .unwrap_or_default();
                (mean(&near).unwrap_or(i as f64), i, id.clone())
            })
            .collect();
        keyed.sort_by(|a, b| a.0.total_cmp(&b.0).then(a.1.cmp(&b.1)));
        columns[c] = keyed.into_iter().map(|k| k.2).collect();
    };
    for _ in 0..SWEEPS {
        for c in 1..count {
            reorder(&mut columns, c, true);
        }
        for c in (0..count.saturating_sub(1)).rev() {
            reorder(&mut columns, c, false);
        }
    }
    let lane: HashSet<&str> = items.iter().filter(|i| i.lane).map(|i| i.id.as_str()).collect();
    let height = |id: &str| if lane.contains(id) { LANE_H } else { NODE_H };
    let mut before: HashMap<&str, Vec<&str>> = HashMap::new();
    let mut after: HashMap<&str, Vec<&str>> = HashMap::new();
    for (from, to) in &links {
        let (cf, ct) = (
            column.get(from).copied().unwrap_or(0),
            column.get(to).copied().unwrap_or(0),
        );
        let (early, late) = match cf.cmp(&ct) {
            std::cmp::Ordering::Less => (from.as_str(), to.as_str()),
            std::cmp::Ordering::Greater => (to.as_str(), from.as_str()),
            std::cmp::Ordering::Equal => continue,
        };
        before.entry(late).or_default().push(early);
        after.entry(early).or_default().push(late);
    }
    let mut centre: HashMap<String, f64> = HashMap::new();
    let centre_of = |centre: &HashMap<String, f64>, ids: Option<&Vec<&str>>| -> Option<f64> {
        let ys: Vec<f64> = ids
            .map(|ids| ids.iter().filter_map(|id| centre.get(*id).copied()).collect())
            .unwrap_or_default();
        mean(&ys)
    };
    let below = |centre: &HashMap<String, f64>, prev: Option<&str>, id: &str| match prev {
        None => height(id) / 2.0,
        Some(p) => centre.get(p).copied().unwrap_or(0.0) + (height(p) + height(id)) / 2.0 + GAP_Y,
    };
    for ids in &columns {
        let mut prev: Option<&str> = None;
        for id in ids {
            let least = below(&centre, prev, id);
            let level = centre_of(&centre, before.get(id.as_str())).unwrap_or(least);
            centre.insert(id.clone(), level.max(least));
            prev = Some(id);
        }
    }
    for ids in columns.iter().rev() {
        let mut prev: Option<&str> = None;
        for id in ids {
            let least = below(&centre, prev, id);
            let root = before.get(id.as_str()).is_none_or(Vec::is_empty);
            let level = if root {
                centre_of(&centre, after.get(id.as_str()))
            } else {
                None
            };
            let now = level.or_else(|| centre.get(id).copied()).unwrap_or(least);
            centre.insert(id.clone(), now.max(least));
            prev = Some(id);
        }
    }
    let step = NODE_W + GAP_X;
    let index: HashMap<&str, usize> = graph
        .nodes
        .iter()
        .enumerate()
        .map(|(i, n)| (n.id.as_str(), i))
        .collect();
    let mut placed: HashMap<&str, (f64, f64)> = HashMap::new();
    let mut nodes = Vec::new();
    for (c, ids) in columns.iter().enumerate() {
        for id in ids {
            if let Some(&i) = index.get(id.as_str()) {
                let xy = (c as f64 * step, centre.get(id).copied().unwrap_or(0.0) - NODE_H / 2.0);
                placed.insert(graph.nodes[i].id.as_str(), xy);
                nodes.push((i, xy.0, xy.1));
            }
        }
    }
    let mut paths = Vec::new();
    for (n, edge) in graph.edges.iter().enumerate() {
        let way = &chains[n];
        let (Some(from), Some(to)) = (placed.get(edge.from.as_str()), placed.get(edge.to.as_str())) else {
            continue;
        };
        if way.is_empty() {
            continue;
        }
        let (mut x, mut y) = (from.0 + NODE_W, from.1 + NODE_H / 2.0);
        let mut path = format!("M {} {}", r(x), r(y));
        for lane_id in &way[1..way.len() - 1] {
            let lx = column.get(lane_id).copied().unwrap_or(0) as f64 * step;
            let ly = centre.get(lane_id).copied().unwrap_or(y);
            path.push_str(&format!(" {} L {} {}", curve(x, y, lx, ly), r(lx + NODE_W), r(ly)));
            x = lx + NODE_W;
            y = ly;
        }
        path.push_str(&format!(" {}", curve(x, y, to.0, to.1 + NODE_H / 2.0)));
        paths.push(path);
    }
    let width = nodes.iter().map(|n| n.1).fold(0.0, f64::max) + if nodes.is_empty() { 0.0 } else { NODE_W };
    let bottom = centre.iter().map(|(id, y)| y + height(id) / 2.0).fold(0.0, f64::max);
    Layout {
        nodes,
        paths,
        width,
        height: bottom,
    }
}

/// `text` cut to `max` characters (never inside one), with an ellipsis.
fn cut(text: &str, max: usize) -> String {
    let clean = clean(text);
    if clean.chars().count() <= max {
        clean
    } else {
        let mut out: String = clean.chars().take(max.saturating_sub(1)).collect();
        out.push('…');
        out
    }
}

/// The diagram as a standalone SVG document; `None` when there is nothing but this PC to draw, or too much.
pub fn svg(graph: &Graph) -> Option<String> {
    if graph.nodes.len() <= 1 || graph.nodes.len() > MAX_NODES {
        return None;
    }
    let laid = layout(graph);
    let pad = 16.0;
    let (w, h) = (laid.width + 2.0 * pad, laid.height + 2.0 * pad);
    let mut out = format!(
        "<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"{}\" height=\"{}\" viewBox=\"0 0 {} {}\" font-family=\"Segoe UI, sans-serif\">\n<rect x=\"0\" y=\"0\" width=\"{}\" height=\"{}\" fill=\"#ffffff\"/>\n<g transform=\"translate({pad} {pad})\">\n",
        r(w),
        r(h),
        r(w),
        r(h),
        r(w),
        r(h)
    );
    for path in &laid.paths {
        out.push_str(&format!(
            "<path d=\"{}\" fill=\"none\" stroke=\"#8c959f\" stroke-width=\"1.5\"/>\n",
            escape(path)
        ));
    }
    for (i, x, y) in &laid.nodes {
        let node = &graph.nodes[*i];
        let (fill, stroke) = match node.kind {
            NodeKind::Pc => ("#eef1f4", "#57606a"),
            NodeKind::Network => ("#ddf4ff", "#0969da"),
            NodeKind::Vm => match node.on {
                Some(true) => ("#dafbe1", "#1a7f37"),
                _ => ("#f6f8fa", "#8c959f"),
            },
            NodeKind::Session => ("#fbefff", "#8250df"),
        };
        out.push_str(&format!(
            "<rect x=\"{}\" y=\"{}\" width=\"{NODE_W}\" height=\"{NODE_H}\" rx=\"6\" fill=\"{fill}\" stroke=\"{stroke}\"/>\n",
            r(*x),
            r(*y)
        ));
        out.push_str(&format!(
            "<text x=\"{}\" y=\"{}\" font-size=\"13\" font-weight=\"600\" fill=\"#1f2328\">{}</text>\n",
            r(x + 10.0),
            r(y + 21.0),
            escape(&cut(&node.label, 26))
        ));
        out.push_str(&format!(
            "<text x=\"{}\" y=\"{}\" font-size=\"11\" fill=\"#59636e\">{}</text>\n",
            r(x + 10.0),
            r(y + 39.0),
            escape(&cut(&node.sub, 32))
        ));
    }
    out.push_str("</g>\n</svg>\n");
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::Environment;

    fn vm(id: &str, name: &str, on: bool) -> VmRecord {
        VmRecord {
            id: id.into(),
            vmx_path: format!("C:\\VMs\\{name}\\{name}.vmx"),
            hypervisor: Hypervisor::Vmware,
            config_path: None,
            display_name: name.into(),
            guest_os: None,
            guest_os_name: None,
            num_vcpus: None,
            memsize_mb: None,
            power_state: if on {
                PowerState::Running
            } else {
                PowerState::NotRunning
            },
            ip_address: Some("192.0.2.10".into()),
            tools_state: None,
            environment: Environment::Lab,
            protected: false,
            tags: Vec::new(),
            last_seen_at: None,
        }
    }

    fn nic(connection: &str) -> VirtualNic {
        VirtualNic {
            connection: Some(connection.into()),
            ..VirtualNic::default()
        }
    }

    #[test]
    fn networks_are_keyed_like_the_map() {
        let k = |h, c: &str, name: Option<&str>| {
            let mut n = nic(c);
            n.network_name = name.map(str::to_owned);
            network_key(h, &n).map(|(key, label, _)| (key, label))
        };
        assert_eq!(
            k(Hypervisor::Vmware, "nat", None),
            Some(("vmware:vmnet8".into(), "NAT (VMnet8)".into()))
        );
        assert_eq!(
            k(Hypervisor::Vmware, "custom (VMnet2)", None),
            Some(("vmware:vmnet2".into(), "VMnet2".into()))
        );
        assert_eq!(
            k(
                Hypervisor::VirtualBox,
                "hostonly",
                Some("VirtualBox Host-Only Ethernet Adapter")
            ),
            Some((
                "virtualbox:hostonly:VirtualBox Host-Only Ethernet Adapter".into(),
                "Host-only: VirtualBox Host-Only Ethernet Adapter".into()
            ))
        );
        assert_eq!(k(Hypervisor::VirtualBox, "none", None), None);
        assert_eq!(k(Hypervisor::Vmware, "", None), None);
        assert_eq!(
            k(Hypervisor::Vmware, "custom (vmnet\u{e9})", None),
            Some(("vmware:custom (vmnet\u{e9})".into(), "custom (vmnet\u{e9})".into())),
            "no panic on odd text"
        );
    }

    #[test]
    fn the_diagram_is_plain_svg_with_escaped_labels() {
        let vms = vec![vm("a", "web<01>", true), vm("b", "db01 \u{202E}x", false)];
        let nics_a = [nic("nat")];
        let nics_b = [nic("nat"), nic("hostonly")];
        let nics = vec![
            VmNics {
                vmx_path: &vms[0].vmx_path,
                hypervisor: Hypervisor::Vmware,
                nics: &nics_a,
            },
            VmNics {
                vmx_path: &vms[1].vmx_path,
                hypervisor: Hypervisor::Vmware,
                nics: &nics_b,
            },
        ];
        let graph = build(&vms, &nics, &[]);
        assert_eq!(graph.nodes.len(), 5, "this PC, two networks, two VMs");
        assert_eq!(graph.edges.len(), 5, "two networks from this PC, three adapters");
        let svg = svg(&graph).unwrap();
        assert!(svg.starts_with("<svg xmlns=\"http://www.w3.org/2000/svg\""));
        assert!(svg.contains("web&lt;01&gt;"));
        assert!(!svg.contains('\u{202E}'));
        for banned in [
            "<script",
            "<a ",
            "href",
            "<image",
            "<foreignObject",
            "<style",
            "url(",
            " onload",
            " onclick",
        ] {
            assert!(!svg.contains(banned), "{banned} in {svg}");
        }
        assert_eq!(svg.matches("<path ").count(), 5);
        assert_eq!(super::svg(&Graph::default()), None);
    }

    #[test]
    fn a_long_edge_runs_through_a_lane() {
        // An edge from this PC to a session crosses the networks' column: it passes through a lane there, never
        // behind a node. (Layers without nodes take no column.)
        let node = |id: &str, kind, layer| Node {
            id: id.into(),
            kind,
            label: id.into(),
            sub: String::new(),
            on: None,
            layer,
        };
        let graph = Graph {
            nodes: vec![
                node("pc", NodeKind::Pc, 0),
                node("net", NodeKind::Network, 1),
                node("s", NodeKind::Session, 3),
            ],
            edges: vec![
                Edge {
                    from: "pc".into(),
                    to: "net".into(),
                },
                Edge {
                    from: "pc".into(),
                    to: "s".into(),
                },
            ],
        };
        let laid = layout(&graph);
        assert_eq!(laid.nodes.len(), 3);
        assert_eq!(laid.paths.len(), 2);
        assert!(!laid.paths[0].contains(" L "), "{}", laid.paths[0]);
        assert!(laid.paths[1].contains(" L "), "{}", laid.paths[1]);
        assert!(laid.width > 0.0 && laid.height > 0.0);
        assert_eq!(cut("abcdef", 4), "abc…");
        assert_eq!(cut("\u{e9}\u{e9}\u{e9}\u{e9}\u{e9}", 3), "\u{e9}\u{e9}…");
    }
}
