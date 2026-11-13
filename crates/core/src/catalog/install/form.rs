//! VM-28: the editor's form, the common parts of every kind of answer file. The file is what is saved; the form is
//! read from it ([`super::read_form`]) and written back into it ([`super::apply_form`]), which changes only the fields
//! that changed, and only their own lines, so the rest of the file stays as it was.
//!
//! Values are the file's own text, placeholders included: a user's password is `{{password.admin}}`, never a password,
//! and their keys `{{ssh_key.admin}}` (or a public key line written into the file).

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum FormField {
    Hostname,
    Locale,
    Keyboard,
    Timezone,
    Storage,
    Network,
    Users,
    Ssh,
    Packages,
    Updates,
    Proxy,
    Mirror,
    LateCommands,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum StorageLayout {
    /// LVM over the whole disk.
    #[default]
    Lvm,
    /// Plain partitions over the whole disk.
    Plain,
    /// A layout of the file's own (partitions written out), which the form shows but doesn't change.
    Custom,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase", rename_all_fields = "camelCase")]
pub enum Swap {
    /// The installer's own choice.
    #[default]
    Auto,
    None,
    SizeMb {
        mb: u32,
    },
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StorageForm {
    pub layout: StorageLayout,
    #[serde(default)]
    pub swap: Swap,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase", rename_all_fields = "camelCase")]
pub enum NetworkForm {
    Dhcp,
    /// `address` is usually `{{ip}}`.
    Static {
        address: String,
        prefix: u8,
        #[serde(default)]
        gateway: Option<String>,
        #[serde(default)]
        dns: Vec<String>,
    },
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UserForm {
    pub name: String,
    /// `{{password.<name>}}`, or `None` for a locked password.
    #[serde(default)]
    pub password: Option<String>,
    /// `{{ssh_key.<name>}}` or public key lines.
    #[serde(default)]
    pub ssh_keys: Vec<String>,
    #[serde(default)]
    pub sudo: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SshForm {
    pub install_server: bool,
    pub password_logins: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Updates {
    None,
    Security,
    All,
}

/// The common parts. `None` and empty lists: the file doesn't set it.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InstallForm {
    #[serde(default)]
    pub hostname: Option<String>,
    #[serde(default)]
    pub locale: Option<String>,
    #[serde(default)]
    pub keyboard: Option<String>,
    #[serde(default)]
    pub timezone: Option<String>,
    #[serde(default)]
    pub storage: Option<StorageForm>,
    #[serde(default)]
    pub network: Option<NetworkForm>,
    #[serde(default)]
    pub users: Vec<UserForm>,
    #[serde(default)]
    pub ssh: Option<SshForm>,
    #[serde(default)]
    pub packages: Vec<String>,
    #[serde(default)]
    pub updates: Option<Updates>,
    #[serde(default)]
    pub proxy: Option<String>,
    #[serde(default)]
    pub mirror: Option<String>,
    #[serde(default)]
    pub late_commands: Vec<String>,
}

/// One field as the form can show it for this file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FieldState {
    pub field: FormField,
    pub editable: bool,
    /// Why it can't be changed here, or what the kind limits.
    pub note: Option<String>,
}

impl FieldState {
    pub fn on(field: FormField) -> Self {
        Self {
            field,
            editable: true,
            note: None,
        }
    }

    pub fn noted(field: FormField, note: impl Into<String>) -> Self {
        Self {
            field,
            editable: true,
            note: Some(note.into()),
        }
    }

    pub fn off(field: FormField, why: impl Into<String>) -> Self {
        Self {
            field,
            editable: false,
            note: Some(why.into()),
        }
    }
}

/// What the form shows for a file: its values, and the fields this kind has.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FormRead {
    pub form: InstallForm,
    pub fields: Vec<FieldState>,
    /// Most users the kind takes in the form.
    pub max_users: Option<u8>,
    /// Why the form can't read the file at all (it isn't valid yet): edit the file.
    pub unreadable: Option<String>,
}

impl FormRead {
    pub fn unreadable(why: impl Into<String>) -> Self {
        Self {
            form: InstallForm::default(),
            fields: Vec::new(),
            max_users: None,
            unreadable: Some(why.into()),
        }
    }

    pub fn editable(&self, field: FormField) -> bool {
        self.fields.iter().any(|f| f.field == field && f.editable)
    }
}

/// A netmask from a prefix length (`24` → `255.255.255.0`).
pub fn netmask(prefix: u8) -> String {
    let bits: u32 = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - u32::from(prefix.min(32)))
    };
    std::net::Ipv4Addr::from(bits).to_string()
}

/// A prefix length from a netmask, when it is one.
pub fn prefix_of(mask: &str) -> Option<u8> {
    let bits = u32::from(mask.trim().parse::<std::net::Ipv4Addr>().ok()?);
    let ones = bits.leading_ones();
    (bits.checked_shl(ones).unwrap_or(0) == 0).then(|| u8::try_from(ones).unwrap_or(32))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn netmasks_and_prefixes() {
        assert_eq!(netmask(24), "255.255.255.0");
        assert_eq!(netmask(0), "0.0.0.0");
        assert_eq!(netmask(32), "255.255.255.255");
        assert_eq!(prefix_of("255.255.255.0"), Some(24));
        assert_eq!(prefix_of("255.255.0.255"), None);
        assert_eq!(prefix_of("x"), None);
        assert_eq!(prefix_of("255.255.255.255"), Some(32));
    }
}
