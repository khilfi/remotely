//! QL-04: the session tree on the left of the Terminal page, grouped the ways the Sessions page
//! sorts and filters: by folder (nested, as on the Sessions page), by tag or by environment label.
//! Built here so the UI only draws it.

use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::{SessionFolder, SessionRecord};
use crate::domain::Environment;

/// How the tree groups sessions.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum TreeGrouping {
    /// Folders and subfolders, sessions outside any folder at the top.
    #[default]
    Folder,
    /// One group per tag; a session with two tags is in both.
    Tag,
    /// SS-06 environment labels, Prod first.
    Label,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum TreeNodeKind {
    Folder,
    Tag,
    Label,
    /// Sessions without a tag or a label.
    Other,
}

/// A group in the tree.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TreeNode {
    /// Stable across reloads, for the UI's open and closed groups: `folder:<id>`, `tag:<name>`,
    /// `label:prod`, `tag:` (no tag), `label:none`.
    pub key: String,
    pub kind: TreeNodeKind,
    pub name: String,
    /// SS-06: the label a label group stands for.
    pub environment: Option<Environment>,
    pub children: Vec<TreeNode>,
    /// Sessions directly in this group, by name.
    pub sessions: Vec<Uuid>,
    /// Sessions in this group and the groups under it (a session counts once).
    pub count: usize,
}

/// The whole tree: groups, then the sessions outside any group (folder grouping only).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionTree {
    pub grouping: TreeGrouping,
    pub nodes: Vec<TreeNode>,
    pub sessions: Vec<Uuid>,
    /// Every session the tree holds, once each, by name.
    pub records: Vec<SessionRecord>,
}

fn by_name(a: &str, b: &str) -> std::cmp::Ordering {
    a.to_lowercase().cmp(&b.to_lowercase()).then_with(|| a.cmp(b))
}

/// Builds the tree from `sessions` (already filtered, by name). `prune`: drop groups left empty, as
/// when the user searches; otherwise empty folders show, like on the Sessions page.
pub fn build(
    grouping: TreeGrouping,
    folders: &[SessionFolder],
    sessions: Vec<SessionRecord>,
    prune: bool,
) -> SessionTree {
    let ids = |list: &[&SessionRecord]| list.iter().map(|s| s.id).collect::<Vec<_>>();
    let (nodes, loose) = match grouping {
        TreeGrouping::Folder => {
            let mut by_folder: HashMap<Option<Uuid>, Vec<&SessionRecord>> = HashMap::new();
            let known: HashSet<Uuid> = folders.iter().map(|f| f.id).collect();
            for s in &sessions {
                // A session whose folder is gone shows at the top rather than vanish.
                let folder = s.folder_id.filter(|f| known.contains(f));
                by_folder.entry(folder).or_default().push(s);
            }
            let nodes = folder_nodes(None, folders, &by_folder, prune, &mut HashSet::new());
            let loose = by_folder.get(&None).map(|l| ids(l)).unwrap_or_default();
            (nodes, loose)
        }
        TreeGrouping::Tag => {
            let mut tags: Vec<String> = Vec::new();
            let mut members: HashMap<String, Vec<&SessionRecord>> = HashMap::new();
            let mut untagged = Vec::new();
            for s in &sessions {
                if s.tags.is_empty() {
                    untagged.push(s);
                }
                for tag in &s.tags {
                    let key = tag.to_lowercase();
                    if !members.contains_key(&key) {
                        tags.push(tag.clone());
                    }
                    members.entry(key).or_default().push(s);
                }
            }
            tags.sort_by(|a, b| by_name(a, b));
            let mut nodes: Vec<TreeNode> = tags
                .iter()
                .map(|tag| {
                    let list = members.get(&tag.to_lowercase()).map(Vec::as_slice).unwrap_or_default();
                    leaf(
                        format!("tag:{}", tag.to_lowercase()),
                        TreeNodeKind::Tag,
                        tag.clone(),
                        None,
                        ids(list),
                    )
                })
                .collect();
            if !untagged.is_empty() {
                nodes.push(leaf(
                    "tag:".into(),
                    TreeNodeKind::Other,
                    "No tag".into(),
                    None,
                    ids(&untagged),
                ));
            }
            (nodes, Vec::new())
        }
        TreeGrouping::Label => {
            let order = [
                (Environment::Prod, "Prod"),
                (Environment::Staging, "Staging"),
                (Environment::Lab, "Lab"),
                (Environment::None, "No label"),
            ];
            let nodes = order
                .iter()
                .filter_map(|(env, name)| {
                    let list: Vec<&SessionRecord> = sessions.iter().filter(|s| s.environment == *env).collect();
                    if list.is_empty() {
                        return None;
                    }
                    let kind = if *env == Environment::None {
                        TreeNodeKind::Other
                    } else {
                        TreeNodeKind::Label
                    };
                    Some(leaf(
                        format!("label:{}", env.as_str()),
                        kind,
                        (*name).to_owned(),
                        Some(*env),
                        ids(&list),
                    ))
                })
                .collect();
            (nodes, Vec::new())
        }
    };
    SessionTree {
        grouping,
        nodes,
        sessions: loose,
        records: sessions,
    }
}

fn leaf(
    key: String,
    kind: TreeNodeKind,
    name: String,
    environment: Option<Environment>,
    sessions: Vec<Uuid>,
) -> TreeNode {
    TreeNode {
        key,
        kind,
        name,
        environment,
        children: Vec::new(),
        count: sessions.len(),
        sessions,
    }
}

/// The folders under `parent`, each with its subfolders and sessions. `seen` stops a broken parent
/// chain from looping.
fn folder_nodes(
    parent: Option<Uuid>,
    folders: &[SessionFolder],
    by_folder: &HashMap<Option<Uuid>, Vec<&SessionRecord>>,
    prune: bool,
    seen: &mut HashSet<Uuid>,
) -> Vec<TreeNode> {
    let mut here: Vec<&SessionFolder> = folders.iter().filter(|f| f.parent_id == parent).collect();
    here.sort_by(|a, b| a.sort_order.cmp(&b.sort_order).then_with(|| by_name(&a.name, &b.name)));
    let mut nodes = Vec::new();
    for folder in here {
        if !seen.insert(folder.id) {
            continue;
        }
        let children = folder_nodes(Some(folder.id), folders, by_folder, prune, seen);
        let sessions: Vec<Uuid> = by_folder
            .get(&Some(folder.id))
            .map(|l| l.iter().map(|s| s.id).collect())
            .unwrap_or_default();
        let count = sessions.len() + children.iter().map(|c| c.count).sum::<usize>();
        if prune && count == 0 {
            continue;
        }
        nodes.push(TreeNode {
            key: format!("folder:{}", folder.id),
            kind: TreeNodeKind::Folder,
            name: folder.name.clone(),
            environment: None,
            children,
            sessions,
            count,
        });
    }
    nodes
}

#[cfg(test)]
mod tests {
    use super::*;

    fn folder(name: &str, parent: Option<Uuid>) -> SessionFolder {
        SessionFolder {
            id: Uuid::new_v4(),
            parent_id: parent,
            name: name.into(),
            sort_order: 0,
        }
    }

    fn session(name: &str, folder: Option<Uuid>, env: Environment, tags: &[&str]) -> SessionRecord {
        SessionRecord {
            id: Uuid::new_v4(),
            folder_id: folder,
            name: name.into(),
            protocol: "ssh".into(),
            host: format!("{name}.example.com"),
            port: 22,
            username: Some("alice".into()),
            auth: super::super::SessionAuth::Agent,
            jump_session_id: None,
            startup_command: None,
            environment: env,
            color: None,
            protected: false,
            tags: tags.iter().map(|t| (*t).to_owned()).collect(),
            vm_id: None,
            imported_from: None,
            created_at: String::new(),
            updated_at: String::new(),
            last_ip: None,
            last_hostname: None,
            last_seen_at: None,
            last_opened_at: None,
        }
    }

    #[test]
    fn folders_nest_with_counts_and_loose_sessions_at_the_top() {
        let customer = folder("Customer A", None);
        let site = folder("Site 1", Some(customer.id));
        let empty = folder("Archive", None);
        let web = session("web01", Some(site.id), Environment::Prod, &[]);
        let db = session("db01", Some(customer.id), Environment::Lab, &[]);
        let lone = session("jump", None, Environment::None, &[]);
        let folders = [customer.clone(), site.clone(), empty.clone()];
        let tree = build(
            TreeGrouping::Folder,
            &folders,
            vec![db.clone(), lone.clone(), web.clone()],
            false,
        );
        let names: Vec<&str> = tree.nodes.iter().map(|n| n.name.as_str()).collect();
        assert_eq!(names, ["Archive", "Customer A"]);
        let a = &tree.nodes[1];
        assert_eq!(a.key, format!("folder:{}", customer.id));
        assert_eq!(a.sessions, [db.id]);
        assert_eq!(a.count, 2);
        assert_eq!(a.children[0].name, "Site 1");
        assert_eq!(a.children[0].sessions, [web.id]);
        assert_eq!(tree.nodes[0].count, 0);
        assert_eq!(tree.sessions, [lone.id]);
        assert_eq!(tree.records.len(), 3);

        // Searching drops the groups that end up empty.
        let found = build(TreeGrouping::Folder, &folders, vec![web.clone()], true);
        assert_eq!(found.nodes.len(), 1);
        assert_eq!(found.nodes[0].children[0].sessions, [web.id]);
        assert!(found.sessions.is_empty());
    }

    #[test]
    fn tags_group_sessions_in_each_of_their_tags() {
        let web = session("web01", None, Environment::None, &["web", "Frontend"]);
        let api = session("api01", None, Environment::None, &["WEB"]);
        let bare = session("bare", None, Environment::None, &[]);
        let tree = build(
            TreeGrouping::Tag,
            &[],
            vec![api.clone(), bare.clone(), web.clone()],
            false,
        );
        let names: Vec<&str> = tree.nodes.iter().map(|n| n.name.as_str()).collect();
        assert_eq!(names, ["Frontend", "WEB", "No tag"]);
        assert_eq!(
            tree.nodes[1].sessions,
            [api.id, web.id],
            "tags match whatever their case"
        );
        assert_eq!(tree.nodes[1].key, "tag:web");
        assert_eq!(tree.nodes[2].kind, TreeNodeKind::Other);
        assert_eq!(tree.nodes[2].sessions, [bare.id]);
        assert!(tree.sessions.is_empty());
    }

    #[test]
    fn labels_put_prod_first_and_skip_empty_ones() {
        let web = session("web01", None, Environment::Prod, &[]);
        let lab = session("lab01", None, Environment::Lab, &[]);
        let other = session("misc", None, Environment::None, &[]);
        let tree = build(
            TreeGrouping::Label,
            &[],
            vec![lab.clone(), other.clone(), web.clone()],
            false,
        );
        let keys: Vec<&str> = tree.nodes.iter().map(|n| n.key.as_str()).collect();
        assert_eq!(keys, ["label:prod", "label:lab", "label:none"]);
        assert_eq!(tree.nodes[0].environment, Some(Environment::Prod));
        assert_eq!(tree.nodes[0].sessions, [web.id]);
        assert_eq!(tree.nodes[2].name, "No label");
    }

    #[test]
    fn a_folder_loop_or_a_missing_folder_does_not_lose_sessions() {
        let mut a = folder("A", None);
        let b = folder("B", Some(a.id));
        a.parent_id = Some(b.id);
        let gone = Uuid::new_v4();
        let orphan = session("orphan", Some(gone), Environment::None, &[]);
        let tree = build(TreeGrouping::Folder, &[a, b], vec![orphan.clone()], false);
        assert!(tree.nodes.is_empty());
        assert_eq!(tree.sessions, [orphan.id]);
    }
}
