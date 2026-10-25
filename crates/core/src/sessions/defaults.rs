//! QL-16 folder defaults: a session folder can set the user, the login (a key, a vault password, the SSH
//! agent, or a password asked when connecting), the jump host, the environment label and tags for the
//! sessions in it and in its subfolders.
//!
//! A session uses its own value first, then the nearest folder up the path that sets one, then the app's
//! default (no user, a password asked when connecting, no jump host, no label, no tags). [`Folders::resolve`]
//! is the one resolver: the store applies it to every session it reads, so terminals, quick connect, MultiExec,
//! Compare and bulk runs, the policy engine's Prod tier bump, key pushes, containers, dashboard polling, host
//! details, reachability, FD-07 and SS-02 all see the values that apply. Only the session editor and FD-07 read
//! what a session sets itself ([`OwnValues`], `SessionRecord::input`).
//!
//! * Tags add up: a session has its own tags and every folder's up the path.
//! * Labels only add: an empty label means "from the folder", and there is no "no label" override, so a folder's
//!   Prod label can't be taken off a session in it by leaving its label empty. A session or a subfolder can
//!   choose another label.
//! * A folder's jump host never applies to itself: the jump host session, when it lives in that folder, uses the
//!   next folder up instead (its own way out). Loops through jump hosts are refused when saving and when
//!   connecting.

use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::{SessionAuth, SessionFolder};
use crate::domain::Environment;
use crate::vault::SecretId;

/// What a folder sets for the sessions in it and in its subfolders. `None` (or an empty list): the folder
/// above decides.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct FolderDefaults {
    pub username: Option<String>,
    /// Never [`SessionAuth::Folder`].
    pub auth: Option<SessionAuth>,
    pub jump_session_id: Option<Uuid>,
    /// No jump host for its sessions, whatever a folder above sets (`jump_session_id` is then `None`).
    pub jump_direct: bool,
    /// Never [`Environment::None`]: a folder adds a label, it can't take one off.
    pub environment: Option<Environment>,
    /// Added to every session's own tags.
    pub tags: Vec<String>,
}

impl FolderDefaults {
    /// Sets nothing: the folder's sessions are as if it had no defaults.
    pub fn is_empty(&self) -> bool {
        *self == Self::default()
    }
}

/// What a session sets itself, for the values a folder can set too: what the session editor edits.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OwnValues {
    /// `None`: from its folders.
    pub username: Option<String>,
    /// [`SessionAuth::Folder`]: from its folders.
    pub auth: SessionAuth,
    pub jump_session_id: Option<Uuid>,
    /// No jump host, whatever its folders set.
    pub jump_direct: bool,
    /// [`Environment::None`]: from its folders.
    pub environment: Environment,
    pub tags: Vec<String>,
}

impl OwnValues {
    /// Sets nothing itself: everything from its folders (what the editor shows a new session gets).
    pub fn from_folders() -> Self {
        Self {
            username: None,
            auth: SessionAuth::Folder,
            jump_session_id: None,
            jump_direct: false,
            environment: Environment::None,
            tags: Vec::new(),
        }
    }
}

/// The folder a value comes from, as the editor names it ("from folder 'Customer A'").
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FromFolder {
    pub id: Uuid,
    pub name: String,
}

/// A tag a session has from a folder: the nearest one that sets it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InheritedTag {
    pub tag: String,
    pub folder: FromFolder,
}

/// Where each value a session doesn't set itself comes from. `None`: the session's own value, or the app's
/// default when neither it nor a folder sets one.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Inherited {
    pub username: Option<FromFolder>,
    pub auth: Option<FromFolder>,
    /// The folder that chose the jump host, or no jump host.
    pub jump: Option<FromFolder>,
    pub environment: Option<FromFolder>,
    /// Tags from folders that the session doesn't have itself.
    pub tags: Vec<InheritedTag>,
}

impl Inherited {
    /// "user and login from folder 'A', label from folder 'B'", for the audit log; empty when nothing is.
    pub fn describe(&self) -> String {
        let mut by_folder: Vec<(&str, Vec<&str>)> = Vec::new();
        let values = [
            (&self.username, "user"),
            (&self.auth, "login"),
            (&self.jump, "jump host"),
            (&self.environment, "label"),
        ];
        for (from, what) in values {
            if let Some(from) = from {
                match by_folder.iter_mut().find(|(name, _)| *name == from.name) {
                    Some((_, list)) => list.push(what),
                    None => by_folder.push((from.name.as_str(), vec![what])),
                }
            }
        }
        let mut parts: Vec<String> = by_folder
            .into_iter()
            .map(|(name, what)| format!("{} from folder '{name}'", and_list(&what)))
            .collect();
        if !self.tags.is_empty() {
            let tags: Vec<&str> = self.tags.iter().map(|t| t.tag.as_str()).collect();
            parts.push(format!("tags {} from folders", tags.join(", ")));
        }
        parts.join(", ")
    }
}

/// "a", "a and b", "a, b and c".
fn and_list(items: &[&str]) -> String {
    match items {
        [] => String::new(),
        [one] => (*one).to_owned(),
        [rest @ .., last] => format!("{} and {last}", rest.join(", ")),
    }
}

/// What applies to a session: its own values, then its folders', then the app's defaults.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Effective {
    pub username: Option<String>,
    /// Never [`SessionAuth::Folder`].
    pub auth: SessionAuth,
    pub jump_session_id: Option<Uuid>,
    pub environment: Environment,
    /// Sorted, without repeats (letter case aside).
    pub tags: Vec<String>,
    pub inherited: Inherited,
}

impl Effective {
    /// SS-04: the vault password the host receives when the session logs in.
    pub(crate) fn sent_secret(&self) -> Option<SecretId> {
        self.auth.sent_secret()
    }
}

/// The app's login for a session that sets none, in a folder that sets none: a password asked when connecting.
pub const APP_DEFAULT_AUTH: SessionAuth = SessionAuth::Password { password_id: None };

/// The session folders with their defaults, to resolve sessions against.
#[derive(Debug, Clone, Default)]
pub struct Folders {
    by_id: HashMap<Uuid, SessionFolder>,
}

impl Folders {
    pub fn new(folders: impl IntoIterator<Item = SessionFolder>) -> Self {
        Self {
            by_id: folders.into_iter().map(|f| (f.id, f)).collect(),
        }
    }

    pub fn get(&self, id: Uuid) -> Option<&SessionFolder> {
        self.by_id.get(&id)
    }

    /// A copy where `folder` has `defaults` (to see what a change would do before saving it).
    pub fn with_defaults(&self, folder: Uuid, defaults: FolderDefaults) -> Self {
        let mut copy = self.clone();
        if let Some(f) = copy.by_id.get_mut(&folder) {
            f.defaults = defaults;
        }
        copy
    }

    /// A copy where `folder` sits under `parent` (a folder move).
    pub fn with_parent(&self, folder: Uuid, parent: Option<Uuid>) -> Self {
        let mut copy = self.clone();
        if let Some(f) = copy.by_id.get_mut(&folder) {
            f.parent_id = parent;
        }
        copy
    }

    /// A copy without `folder`, its subfolders moved up to its parent (a folder deleted).
    pub fn without(&self, folder: Uuid) -> Self {
        let mut copy = self.clone();
        let parent = copy.by_id.remove(&folder).and_then(|f| f.parent_id);
        for f in copy.by_id.values_mut() {
            if f.parent_id == Some(folder) {
                f.parent_id = parent;
            }
        }
        copy
    }

    /// The folder and those above it, nearest first. A loop (which a checked tree never has) stops the walk.
    pub fn path(&self, folder: Option<Uuid>) -> Vec<&SessionFolder> {
        let mut path = Vec::new();
        let mut seen = HashSet::new();
        let mut next = folder;
        while let Some(id) = next {
            if !seen.insert(id) {
                break;
            }
            let Some(f) = self.by_id.get(&id) else {
                break;
            };
            path.push(f);
            next = f.parent_id;
        }
        path
    }

    /// Whether `folder` is `ancestor` or lies under it.
    pub fn is_within(&self, folder: Option<Uuid>, ancestor: Uuid) -> bool {
        self.path(folder).iter().any(|f| f.id == ancestor)
    }

    /// QL-16: the one resolver. `session` is the session's id (a saved one; `None` for one not saved yet), so a
    /// folder whose jump host is that session doesn't send it through itself.
    pub fn resolve(&self, session: Option<Uuid>, own: &OwnValues, folder: Option<Uuid>) -> Effective {
        let path = self.path(folder);
        let from = |f: &SessionFolder| FromFolder {
            id: f.id,
            name: f.name.clone(),
        };
        let mut inherited = Inherited::default();

        let username = match &own.username {
            Some(user) => Some(user.clone()),
            None => path.iter().find_map(|f| {
                f.defaults
                    .username
                    .clone()
                    .inspect(|_| inherited.username = Some(from(f)))
            }),
        };

        let auth = match &own.auth {
            SessionAuth::Folder => path
                .iter()
                .find_map(|f| {
                    f.defaults
                        .auth
                        .clone()
                        .filter(|a| *a != SessionAuth::Folder)
                        .inspect(|_| inherited.auth = Some(from(f)))
                })
                .unwrap_or(APP_DEFAULT_AUTH),
            auth => auth.clone(),
        };

        let jump_session_id = if own.jump_session_id.is_some() {
            own.jump_session_id
        } else if own.jump_direct {
            None
        } else {
            let mut found = None;
            for f in &path {
                if f.defaults.jump_direct {
                    inherited.jump = Some(from(f));
                    break;
                }
                match f.defaults.jump_session_id {
                    // A folder's jump host never goes through itself: it uses the next folder up.
                    Some(jump) if Some(jump) == session => continue,
                    Some(jump) => {
                        inherited.jump = Some(from(f));
                        found = Some(jump);
                        break;
                    }
                    None => {}
                }
            }
            found
        };

        let environment = match own.environment {
            Environment::None => path
                .iter()
                .find_map(|f| {
                    f.defaults
                        .environment
                        .filter(|e| *e != Environment::None)
                        .inspect(|_| inherited.environment = Some(from(f)))
                })
                .unwrap_or(Environment::None),
            env => env,
        };

        let mut tags = own.tags.clone();
        let mut seen: HashSet<String> = tags.iter().map(|t| t.to_lowercase()).collect();
        for f in &path {
            for tag in &f.defaults.tags {
                if seen.insert(tag.to_lowercase()) {
                    tags.push(tag.clone());
                    inherited.tags.push(InheritedTag {
                        tag: tag.clone(),
                        folder: from(f),
                    });
                }
            }
        }
        tags.sort_by_key(|t| t.to_lowercase());
        inherited.tags.sort_by_key(|t| t.tag.to_lowercase());

        Effective {
            username,
            auth,
            jump_session_id,
            environment,
            tags,
            inherited,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn folder(name: &str, parent: Option<&SessionFolder>, defaults: FolderDefaults) -> SessionFolder {
        SessionFolder {
            id: Uuid::new_v4(),
            parent_id: parent.map(|p| p.id),
            name: name.into(),
            sort_order: 0,
            defaults,
        }
    }

    fn own() -> OwnValues {
        OwnValues {
            username: None,
            auth: SessionAuth::Folder,
            jump_session_id: None,
            jump_direct: false,
            environment: Environment::None,
            tags: vec![],
        }
    }

    fn key(id: Uuid) -> SessionAuth {
        SessionAuth::Key {
            key_id: Some(SecretId(id)),
            passphrase_id: None,
        }
    }

    fn password(id: Uuid) -> SessionAuth {
        SessionAuth::Password {
            password_id: Some(SecretId(id)),
        }
    }

    #[test]
    fn a_session_value_wins_over_its_folder_which_wins_over_the_folder_above_then_the_app_default() {
        let jump_outer = Uuid::new_v4();
        let jump_inner = Uuid::new_v4();
        let (k1, k2) = (Uuid::new_v4(), Uuid::new_v4());
        let customer = folder(
            "Customer A",
            None,
            FolderDefaults {
                username: Some("alice".into()),
                auth: Some(key(k1)),
                jump_session_id: Some(jump_outer),
                environment: Some(Environment::Prod),
                tags: vec!["acme".into()],
                ..FolderDefaults::default()
            },
        );
        let web = folder(
            "Web",
            Some(&customer),
            FolderDefaults {
                auth: Some(key(k2)),
                jump_session_id: Some(jump_inner),
                tags: vec!["web".into()],
                ..FolderDefaults::default()
            },
        );
        let folders = Folders::new([customer.clone(), web.clone()]);

        // Nothing set on the session: the nearest folder for each value, the one above for the rest.
        let got = folders.resolve(None, &own(), Some(web.id));
        assert_eq!(got.username.as_deref(), Some("alice"));
        assert_eq!(got.inherited.username.as_ref().unwrap().name, "Customer A");
        assert_eq!(got.auth, key(k2));
        assert_eq!(got.inherited.auth.as_ref().unwrap().name, "Web");
        assert_eq!(got.jump_session_id, Some(jump_inner));
        assert_eq!(got.environment, Environment::Prod);
        assert_eq!(got.inherited.environment.as_ref().unwrap().name, "Customer A");
        assert_eq!(got.tags, vec!["acme".to_owned(), "web".to_owned()]);

        // The session's own values win, and its tags add to the folders'.
        let mine = OwnValues {
            username: Some("bob".into()),
            auth: SessionAuth::Agent,
            jump_session_id: None,
            jump_direct: true,
            environment: Environment::Lab,
            tags: vec!["db".into(), "Web".into()],
        };
        let got = folders.resolve(None, &mine, Some(web.id));
        assert_eq!(got.username.as_deref(), Some("bob"));
        assert_eq!(got.auth, SessionAuth::Agent);
        assert_eq!(got.jump_session_id, None);
        assert_eq!(got.environment, Environment::Lab);
        assert_eq!(got.tags, vec!["acme".to_owned(), "db".to_owned(), "Web".to_owned()]);
        assert_eq!(got.inherited.tags.len(), 1);
        assert_eq!(
            got.inherited,
            Inherited {
                tags: vec![InheritedTag {
                    tag: "acme".into(),
                    folder: FromFolder {
                        id: customer.id,
                        name: "Customer A".into()
                    }
                }],
                ..Inherited::default()
            }
        );

        // Outside every folder: the app's defaults.
        let got = folders.resolve(None, &own(), None);
        assert_eq!(got.username, None);
        assert_eq!(got.auth, APP_DEFAULT_AUTH);
        assert_eq!(got.jump_session_id, None);
        assert_eq!(got.environment, Environment::None);
        assert!(got.tags.is_empty());
        assert_eq!(got.inherited, Inherited::default());
    }

    #[test]
    fn a_folder_above_decides_what_the_nearer_one_leaves_open() {
        let p = Uuid::new_v4();
        let top = folder(
            "Top",
            None,
            FolderDefaults {
                auth: Some(password(p)),
                ..FolderDefaults::default()
            },
        );
        let mid = folder("Middle", Some(&top), FolderDefaults::default());
        let low = folder(
            "Low",
            Some(&mid),
            FolderDefaults {
                username: Some("alice".into()),
                ..FolderDefaults::default()
            },
        );
        let folders = Folders::new([top.clone(), mid, low.clone()]);
        let got = folders.resolve(None, &own(), Some(low.id));
        assert_eq!(got.auth, password(p));
        assert_eq!(got.sent_secret(), Some(SecretId(p)));
        assert_eq!(got.inherited.auth.unwrap().id, top.id);
        assert_eq!(got.inherited.username.unwrap().id, low.id);
    }

    #[test]
    fn a_subfolder_can_go_direct_and_a_jump_host_never_goes_through_itself() {
        let outer = Uuid::new_v4();
        let inner = Uuid::new_v4();
        let customer = folder(
            "Customer",
            None,
            FolderDefaults {
                jump_session_id: Some(outer),
                ..FolderDefaults::default()
            },
        );
        let dmz = folder(
            "DMZ",
            Some(&customer),
            FolderDefaults {
                jump_session_id: Some(inner),
                ..FolderDefaults::default()
            },
        );
        let lan = folder(
            "Office",
            Some(&customer),
            FolderDefaults {
                jump_direct: true,
                ..FolderDefaults::default()
            },
        );
        let folders = Folders::new([customer.clone(), dmz.clone(), lan.clone()]);
        // The inner jump host lives in DMZ: it goes out through the outer one, not through itself.
        let got = folders.resolve(Some(inner), &own(), Some(dmz.id));
        assert_eq!(got.jump_session_id, Some(outer));
        assert_eq!(got.inherited.jump.unwrap().id, customer.id);
        // Another session in DMZ goes through the inner one.
        assert_eq!(
            folders
                .resolve(Some(Uuid::new_v4()), &own(), Some(dmz.id))
                .jump_session_id,
            Some(inner)
        );
        // Office goes direct, whatever Customer says, and says where that comes from.
        let got = folders.resolve(None, &own(), Some(lan.id));
        assert_eq!(got.jump_session_id, None);
        assert_eq!(got.inherited.jump.unwrap().id, lan.id);
        // A session's own jump host wins over all of them.
        let mut mine = own();
        mine.jump_session_id = Some(outer);
        assert_eq!(folders.resolve(None, &mine, Some(lan.id)).jump_session_id, Some(outer));
    }

    #[test]
    fn an_empty_label_takes_the_folders_label_and_a_session_label_wins() {
        let prod = folder(
            "Prod",
            None,
            FolderDefaults {
                environment: Some(Environment::Prod),
                ..FolderDefaults::default()
            },
        );
        let folders = Folders::new([prod.clone()]);
        assert_eq!(
            folders.resolve(None, &own(), Some(prod.id)).environment,
            Environment::Prod
        );
        let mut mine = own();
        mine.environment = Environment::Staging;
        assert_eq!(
            folders.resolve(None, &mine, Some(prod.id)).environment,
            Environment::Staging
        );
    }

    #[test]
    fn a_loop_in_the_folder_tree_stops_the_walk() {
        let mut a = folder("A", None, FolderDefaults::default());
        let b = folder(
            "B",
            Some(&a),
            FolderDefaults {
                username: Some("alice".into()),
                ..FolderDefaults::default()
            },
        );
        a.parent_id = Some(b.id);
        let folders = Folders::new([a.clone(), b]);
        assert_eq!(folders.path(Some(a.id)).len(), 2);
        assert_eq!(
            folders.resolve(None, &own(), Some(a.id)).username.as_deref(),
            Some("alice")
        );
    }

    #[test]
    fn moved_and_removed_folders_change_what_is_inherited() {
        let p = Uuid::new_v4();
        let top = folder(
            "Top",
            None,
            FolderDefaults {
                auth: Some(password(p)),
                ..FolderDefaults::default()
            },
        );
        let other = folder("Other", None, FolderDefaults::default());
        let low = folder("Low", Some(&other), FolderDefaults::default());
        let folders = Folders::new([top.clone(), other.clone(), low.clone()]);
        assert_eq!(folders.resolve(None, &own(), Some(low.id)).auth, APP_DEFAULT_AUTH);
        let moved = folders.with_parent(low.id, Some(top.id));
        assert_eq!(moved.resolve(None, &own(), Some(low.id)).auth, password(p));
        assert!(moved.is_within(Some(low.id), top.id));
        let gone = moved.without(low.id);
        assert!(gone.get(low.id).is_none());
        let changed = folders.with_defaults(
            other.id,
            FolderDefaults {
                username: Some("bob".into()),
                ..FolderDefaults::default()
            },
        );
        assert_eq!(
            changed.resolve(None, &own(), Some(low.id)).username.as_deref(),
            Some("bob")
        );
    }

    #[test]
    fn inherited_values_are_described_by_folder() {
        let a = FromFolder {
            id: Uuid::nil(),
            name: "A".into(),
        };
        let b = FromFolder {
            id: Uuid::nil(),
            name: "B".into(),
        };
        let inherited = Inherited {
            username: Some(a.clone()),
            auth: Some(a.clone()),
            jump: None,
            environment: Some(b),
            tags: vec![InheritedTag {
                tag: "web".into(),
                folder: a,
            }],
        };
        assert_eq!(
            inherited.describe(),
            "user and login from folder 'A', label from folder 'B', tags web from folders"
        );
        assert_eq!(Inherited::default().describe(), "");
    }
}
