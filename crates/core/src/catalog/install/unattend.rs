//! VM-28: Windows Setup's `autounattend.xml` (Windows Server 2022 and 2025), read as untrusted ([`super::xml`]).
//!
//! An unattend file is `<settings pass="...">` sections of `<component name="Microsoft-Windows-...">` settings. A
//! password can't be a hash here, so `{{password.<name>}}` renders as a one-time password with `<PlainText>true`,
//! which G6 replaces over WinRM once the install is done; so the file turns WinRM over HTTPS on (the starters do), and
//! the lint warns when it doesn't. The form changes the text of single elements and the first-logon commands.

use super::form::{FieldState, FormField, FormRead, InstallForm, UserForm};
use super::xml::{self, Element};
use super::{is_sample_secret, looks_hashed, ConfigProblem, Severity};

const PASSES: &[&str] = &[
    "windowsPE",
    "offlineServicing",
    "generalize",
    "specialize",
    "auditSystem",
    "auditUser",
    "oobeSystem",
];

const SHELL: &str = "Microsoft-Windows-Shell-Setup";
const INTERNATIONAL: &str = "Microsoft-Windows-International-Core";
const SETUP: &str = "Microsoft-Windows-Setup";

/// Well-formed XML whose root is `<unattend>`.
pub fn syntax(text: &str) -> Vec<ConfigProblem> {
    match xml::parse(text) {
        Err(err) => vec![ConfigProblem::error(
            Some(err.line),
            format!("This isn't well-formed XML: {}", err.message),
        )],
        Ok(root) if root.local() != "unattend" => vec![ConfigProblem::error(
            Some(root.line),
            format!("The root element is <{}>: an answer file's is <unattend>.", root.name),
        )],
        Ok(_) => Vec::new(),
    }
}

fn component<'a>(root: &'a Element, pass: &str, name: &str) -> Option<&'a Element> {
    root.children_named("settings")
        .filter(|s| s.attr("pass") == Some(pass))
        .flat_map(|s| s.children_named("component"))
        .find(|c| c.attr("name") == Some(name))
}

fn components<'a>(root: &'a Element, name: &'a str) -> impl Iterator<Item = &'a Element> + 'a {
    root.children_named("settings")
        .flat_map(|s| s.children_named("component"))
        .filter(move |c| c.attr("name") == Some(name))
}

fn all<'a>(root: &'a Element, local: &str) -> Vec<&'a Element> {
    let mut out = Vec::new();
    root.find_all(local, &mut out);
    out
}

pub fn check(text: &str) -> Vec<ConfigProblem> {
    let mut out = syntax(text);
    let root = match xml::parse(text) {
        Ok(root) => root,
        Err(err) => {
            // Not well formed: it can't be checked for a password written into it, so it isn't saved (review of #88).
            out.push(ConfigProblem::secret(
                Some(err.line),
                "Remotely can't read this file's XML to check it for passwords, so it can't be saved until it is well formed.",
            ));
            return out;
        }
    };
    // Secrets first, whatever else is wrong.
    let syntax_failed = !out.is_empty();
    out.extend(secrets(&root));
    if syntax_failed {
        return out;
    }
    if root.attr("xmlns") != Some("urn:schemas-microsoft-com:unattend") {
        out.push(ConfigProblem::warning(
            Some(root.line),
            "<unattend> needs xmlns=\"urn:schemas-microsoft-com:unattend\", or Setup ignores the file.",
        ));
    }
    let mut seen = Vec::new();
    for s in root.children_named("settings") {
        match s.attr("pass") {
            Some(p) if PASSES.contains(&p) => {
                if seen.contains(&p) {
                    out.push(ConfigProblem::warning(
                        Some(s.line),
                        format!("The {p} pass is set twice."),
                    ));
                }
                seen.push(p);
            }
            Some(p) => out.push(ConfigProblem::error(
                Some(s.line),
                format!("{p} isn't a Setup pass: use windowsPE, specialize, oobeSystem and the like."),
            )),
            None => out.push(ConfigProblem::error(Some(s.line), "<settings> needs its pass.")),
        }
        for c in s.children_named("component") {
            if c.attr("name").is_none() || c.attr("processorArchitecture").is_none() {
                out.push(ConfigProblem::warning(
                    Some(c.line),
                    "A <component> needs name and processorArchitecture, or Setup skips it.",
                ));
            }
        }
    }
    for k in all(&root, "ProductKey") {
        let key = k.child("Key").map_or(k.trimmed(), Element::trimmed);
        if !key.is_empty() {
            out.push(ConfigProblem::warning(
                Some(k.line),
                "A product key is your licence's: it travels with the config in exports.",
            ));
        }
    }
    out.extend(asks(&root));
    out.sort_by_key(|p| (p.line.unwrap_or(u32::MAX), p.severity == Severity::Warning));
    out
}

/// Every password's value is Remotely's, or empty.
fn secrets(root: &Element) -> Vec<ConfigProblem> {
    let mut out = Vec::new();
    for p in all(root, "Password")
        .into_iter()
        .chain(all(root, "AdministratorPassword"))
    {
        let (value, line) = match p.child("Value") {
            Some(v) => (v.trimmed().to_owned(), v.line),
            None if p.children.is_empty() => (p.trimmed().to_owned(), p.line),
            None => continue,
        };
        if value.is_empty() {
            continue;
        }
        if is_sample_secret(&value) {
            if p.child("PlainText")
                .is_some_and(|t| !t.trimmed().eq_ignore_ascii_case("true"))
            {
                out.push(ConfigProblem::error(
                    Some(p.line),
                    "PlainText has to be true: Remotely writes a one-time password, which Windows reads as plain text.",
                ));
            }
            continue;
        }
        let what = if looks_hashed(&value) {
            "a password hash"
        } else {
            "a password"
        };
        out.push(ConfigProblem::secret(Some(line), format!("<{}> holds {what}: a config never keeps one. Pick it from the vault in the form, or write {{{{password.<name>}}}}.", p.name)));
    }
    out
}

/// What Setup would stop to ask, an account to sign in with, and WinRM over HTTPS.
fn asks(root: &Element) -> Vec<ConfigProblem> {
    let mut out = Vec::new();
    let setup = component(root, "windowsPE", SETUP);
    match setup {
        None => out.push(ConfigProblem::warning(
            None,
            "No Microsoft-Windows-Setup in windowsPE: Setup asks for the disk, the edition and the licence.",
        )),
        Some(s) => {
            if s.at(&["UserData", "AcceptEula"])
                .is_none_or(|a| !a.trimmed().eq_ignore_ascii_case("true"))
            {
                out.push(ConfigProblem::warning(
                    Some(s.line),
                    "Setup asks to accept the licence: add UserData/AcceptEula true.",
                ));
            }
            if s.at(&["ImageInstall", "OSImage", "InstallFrom", "MetaData"]).is_none()
                && s.at(&["UserData", "ProductKey"]).is_none()
            {
                out.push(ConfigProblem::warning(
                    Some(s.line),
                    "Setup asks which edition to install: name it under ImageInstall/OSImage/InstallFrom/MetaData.",
                ));
            }
            if s.child("DiskConfiguration").is_none() && s.at(&["ImageInstall", "OSImage", "InstallTo"]).is_none() {
                out.push(ConfigProblem::warning(
                    Some(s.line),
                    "Setup asks where to install: add DiskConfiguration and InstallTo.",
                ));
            }
        }
    }
    let admin = components(root, SHELL).find_map(|c| c.at(&["UserAccounts", "AdministratorPassword"]));
    let local = components(root, SHELL).any(|c| c.at(&["UserAccounts", "LocalAccounts", "LocalAccount"]).is_some());
    if admin.is_none() && !local {
        out.push(ConfigProblem::error(
            None,
            "No account to sign in with: give the Administrator a password in the form.",
        ));
    }
    if component(root, "oobeSystem", SHELL)
        .and_then(|c| c.child("OOBE"))
        .is_none()
    {
        out.push(ConfigProblem::warning(
            None,
            "Windows asks its first-start questions: hide them under oobeSystem's OOBE.",
        ));
    }
    let commands: Vec<String> = all(root, "CommandLine")
        .iter()
        .map(|c| c.trimmed().to_ascii_lowercase())
        .collect();
    if !commands
        .iter()
        .any(|c| c.contains("winrm") || c.contains("5986") || c.contains("enable-psremoting"))
    {
        out.push(ConfigProblem::warning(
            None,
            "WinRM over HTTPS isn't turned on: Remotely can't reach the VM, or set its password, after the install.",
        ));
    }
    out.sort_by_key(|p| (p.line.unwrap_or(u32::MAX), p.severity == Severity::Warning));
    out
}

/// The partitions DiskConfiguration sizes (MB), the one that extends left out.
pub fn disk_need_mb(text: &str) -> Option<u64> {
    let root = xml::parse(text).ok()?;
    let sizes: Vec<u64> = all(&root, "CreatePartition")
        .into_iter()
        .filter(|p| {
            p.child("Extend")
                .is_none_or(|e| !e.trimmed().eq_ignore_ascii_case("true"))
        })
        .filter_map(|p| p.child("Size")?.trimmed().parse().ok())
        .collect();
    (!sizes.is_empty()).then(|| sizes.iter().sum())
}

// ---- The form -------------------------------------------------------------------------------------------------------

fn fields() -> Vec<FieldState> {
    let raw = "Set it in the file: Windows' answer file has its own settings for this.";
    vec![
        FieldState::on(FormField::Hostname),
        FieldState::noted(
            FormField::Locale,
            "Such as en-US: the system, user and display languages.",
        ),
        FieldState::noted(FormField::Keyboard, "Such as en-US or 0409:00000409."),
        FieldState::noted(
            FormField::Timezone,
            "Windows' own names, such as UTC or W. Europe Standard Time.",
        ),
        FieldState::off(FormField::Storage, raw),
        FieldState::off(FormField::Network, raw),
        FieldState::noted(
            FormField::Users,
            "The Administrator's password; more accounts go in the file.",
        ),
        FieldState::off(
            FormField::Ssh,
            "Windows is reached over WinRM: the starters turn it on.",
        ),
        FieldState::off(FormField::Packages, raw),
        FieldState::off(FormField::Updates, raw),
        FieldState::off(FormField::Proxy, raw),
        FieldState::off(FormField::Mirror, raw),
        FieldState::noted(FormField::LateCommands, "Run at the first sign-in, in order."),
    ]
}

fn text_of(e: Option<&Element>) -> Option<String> {
    e.map(|e| e.trimmed().to_owned()).filter(|t| !t.is_empty())
}

fn first_logon(root: &Element) -> Option<&Element> {
    component(root, "oobeSystem", SHELL).and_then(|c| c.child("FirstLogonCommands"))
}

fn ordered_commands(fl: &Element) -> Vec<(u32, &Element)> {
    let mut list: Vec<(u32, &Element)> = fl
        .children_named("SynchronousCommand")
        .map(|c| {
            (
                c.child("Order")
                    .and_then(|o| o.trimmed().parse().ok())
                    .unwrap_or(u32::MAX),
                c,
            )
        })
        .collect();
    list.sort_by_key(|(o, _)| *o);
    list
}

pub fn read_form(body: &str) -> FormRead {
    let root = match xml::parse(body) {
        Err(err) => return FormRead::unreadable(format!("Line {}: {}", err.line, err.message)),
        Ok(root) => root,
    };
    let shell = |name: &str| components(&root, SHELL).find_map(|c| c.child(name));
    let intl = components(&root, INTERNATIONAL).last();
    let admin = components(&root, SHELL).find_map(|c| c.at(&["UserAccounts", "AdministratorPassword", "Value"]));
    let users = admin
        .map(|v| {
            vec![UserForm {
                name: "Administrator".into(),
                password: text_of(Some(v)),
                ssh_keys: Vec::new(),
                sudo: true,
            }]
        })
        .unwrap_or_default();
    let mut fields = fields();
    let late = first_logon(&root).map(|fl| {
        ordered_commands(fl)
            .into_iter()
            .filter_map(|(_, c)| text_of(c.child("CommandLine")))
            .collect()
    });
    if component(&root, "oobeSystem", SHELL).is_none() {
        super::cloud_init::set_off(
            &mut fields,
            FormField::LateCommands,
            "The file has no Microsoft-Windows-Shell-Setup in oobeSystem to add commands to.",
        );
    }
    if component(&root, "specialize", SHELL).is_none() && shell("ComputerName").is_none() {
        super::cloud_init::set_off(
            &mut fields,
            FormField::Hostname,
            "The file has no Microsoft-Windows-Shell-Setup in specialize to name the computer in.",
        );
    }
    if intl.is_none() {
        for f in [FormField::Locale, FormField::Keyboard] {
            super::cloud_init::set_off(
                &mut fields,
                f,
                "The file has no Microsoft-Windows-International-Core component.",
            );
        }
    }
    if components(&root, SHELL).next().is_none() {
        super::cloud_init::set_off(
            &mut fields,
            FormField::Timezone,
            "The file has no Microsoft-Windows-Shell-Setup component.",
        );
    }
    if admin.is_none() {
        super::cloud_init::set_off(
            &mut fields,
            FormField::Users,
            "The file has no AdministratorPassword: add it in the file first.",
        );
    }
    let form = InstallForm {
        hostname: text_of(shell("ComputerName")),
        locale: text_of(intl.and_then(|i| i.child("UserLocale").or_else(|| i.child("SystemLocale")))),
        keyboard: text_of(intl.and_then(|i| i.child("InputLocale"))),
        timezone: text_of(shell("TimeZone")),
        users,
        late_commands: late.unwrap_or_default(),
        ..InstallForm::default()
    };
    FormRead {
        form,
        fields,
        max_users: Some(1),
        unreadable: None,
    }
}

/// `text` with `parent`'s child `name` set to `value`: its text changed, or the element added before the parent ends.
fn set_child(text: &str, parent: &Element, name: &str, value: &str) -> Result<String, String> {
    if let Some(child) = parent.child(name) {
        return xml::set_text(text, child, value)
            .ok_or_else(|| format!("<{name}> holds other elements: edit it in the file."));
    }
    Ok(insert_child(
        text,
        parent,
        &format!("<{name}>{}</{name}>", xml::escape(value)),
    ))
}

fn insert_child(text: &str, parent: &Element, element: &str) -> String {
    let close = parent.close_start;
    let line_start = text[..close].rfind('\n').map_or(0, |i| i + 1);
    let alone = text[line_start..close].trim().is_empty();
    let child_indent = parent
        .children
        .last()
        .map(|c| xml::indent_at(text, c.start))
        .unwrap_or_else(|| format!("{}  ", xml::indent_at(text, parent.start)));
    let mut out = String::with_capacity(text.len() + element.len() + 8);
    if alone {
        out.push_str(&text[..line_start]);
        out.push_str(&child_indent);
        out.push_str(element);
        out.push('\n');
        out.push_str(&text[line_start..]);
    } else {
        out.push_str(&text[..close]);
        out.push_str(element);
        out.push_str(&text[close..]);
    }
    out
}

/// Each step parses the text again, so every element's place is right.
fn step(text: &str, f: impl FnOnce(&str, &Element) -> Result<String, String>) -> Result<String, String> {
    let root = xml::parse(text).map_err(|e| format!("Line {}: {}", e.line, e.message))?;
    f(text, &root)
}

pub fn apply_form(
    body: &str,
    _before: &InstallForm,
    after: &InstallForm,
    changed: &[FormField],
) -> Result<String, String> {
    let mut text = body.to_owned();
    let need = |v: &Option<String>, what: &str| -> Result<String, String> {
        v.as_deref()
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .map(str::to_owned)
            .ok_or_else(|| format!("Give the {what}: Windows' answer file needs one here."))
    };
    for field in changed {
        text = match field {
            FormField::Hostname => {
                let v = need(&after.hostname, "computer name")?;
                step(&text, |t, root| {
                    let c = component(root, "specialize", SHELL)
                        .or_else(|| components(root, SHELL).find(|c| c.child("ComputerName").is_some()))
                        .ok_or("No Microsoft-Windows-Shell-Setup component to name the computer in.")?;
                    set_child(t, c, "ComputerName", &v)
                })?
            }
            FormField::Timezone => {
                let v = need(&after.timezone, "time zone")?;
                step(&text, |t, root| {
                    let c = components(root, SHELL)
                        .find(|c| c.child("TimeZone").is_some())
                        .or_else(|| component(root, "specialize", SHELL))
                        .or_else(|| components(root, SHELL).next())
                        .ok_or("No Microsoft-Windows-Shell-Setup component for the time zone.")?;
                    set_child(t, c, "TimeZone", &v)
                })?
            }
            FormField::Locale => {
                let v = need(&after.locale, "locale")?;
                let mut t = text.clone();
                for name in ["SystemLocale", "UserLocale", "UILanguage"] {
                    t = step(&t, |t, root| {
                        let Some(intl) = components(root, INTERNATIONAL).last() else {
                            return Err("No Microsoft-Windows-International-Core component.".into());
                        };
                        if intl.child(name).is_none() && name != "UserLocale" {
                            return Ok(t.to_owned());
                        }
                        set_child(t, intl, name, &v)
                    })?;
                }
                t
            }
            FormField::Keyboard => {
                let v = need(&after.keyboard, "keyboard")?;
                step(&text, |t, root| {
                    let intl = components(root, INTERNATIONAL)
                        .last()
                        .ok_or("No Microsoft-Windows-International-Core component.")?;
                    set_child(t, intl, "InputLocale", &v)
                })?
            }
            FormField::Users => {
                let [user] = after.users.as_slice() else {
                    return Err(
                        "Windows' answer file keeps the Administrator here; more accounts go in the file.".into(),
                    );
                };
                if !user.name.eq_ignore_ascii_case("Administrator") {
                    return Err("The form sets the Administrator's password; other accounts go in the file.".into());
                }
                let pw = user
                    .password
                    .as_deref()
                    .map(str::trim)
                    .filter(|p| !p.is_empty())
                    .ok_or("The Administrator needs a password: pick it from the vault.")?;
                let pw = pw.to_owned();
                step(&text, |t, root| {
                    let v = components(root, SHELL)
                        .find_map(|c| c.at(&["UserAccounts", "AdministratorPassword", "Value"]))
                        .ok_or("The file has no AdministratorPassword.")?;
                    xml::set_text(t, v, &pw).ok_or_else(|| "The password's Value holds other elements.".to_owned())
                })?
            }
            FormField::LateCommands => {
                let commands: Vec<String> = after
                    .late_commands
                    .iter()
                    .map(|c| c.trim().to_owned())
                    .filter(|c| !c.is_empty())
                    .collect();
                step(&text, |t, root| {
                    let c = component(root, "oobeSystem", SHELL)
                        .ok_or("No Microsoft-Windows-Shell-Setup in oobeSystem.")?;
                    let old = c.child("FirstLogonCommands");
                    let descriptions: Vec<Option<String>> = old
                        .map(|fl| {
                            ordered_commands(fl)
                                .into_iter()
                                .map(|(_, sc)| text_of(sc.child("Description")))
                                .collect()
                        })
                        .unwrap_or_default();
                    let indent = old.map_or_else(
                        || {
                            c.children.last().map_or_else(
                                || format!("{}  ", xml::indent_at(t, c.start)),
                                |l| xml::indent_at(t, l.start),
                            )
                        },
                        |fl| xml::indent_at(t, fl.start),
                    );
                    let element = first_logon_xml(&commands, &descriptions, &indent);
                    match (old, element) {
                        (Some(fl), Some(el)) => Ok(format!("{}{}{}", &t[..fl.start], el.trim_start(), &t[fl.end..])),
                        (Some(fl), None) => Ok(remove(t, fl)),
                        (None, Some(el)) => Ok(insert_child(t, c, el.trim_start())),
                        (None, None) => Ok(t.to_owned()),
                    }
                })?
            }
            _ => return Err("The form doesn't set that in a Windows answer file: edit the file.".into()),
        };
    }
    xml::parse(&text).map_err(|e| format!("The form's change would break the file: {}", e.message))?;
    Ok(text)
}

/// The element and its line when it is alone on it.
fn remove(text: &str, e: &Element) -> String {
    let line_start = text[..e.start].rfind('\n').map_or(0, |i| i + 1);
    let line_end = text[e.end..].find('\n').map_or(text.len(), |i| e.end + i + 1);
    if text[line_start..e.start].trim().is_empty() && text[e.end..line_end].trim().is_empty() {
        format!("{}{}", &text[..line_start], &text[line_end..])
    } else {
        format!("{}{}", &text[..e.start], &text[e.end..])
    }
}

fn first_logon_xml(commands: &[String], descriptions: &[Option<String>], indent: &str) -> Option<String> {
    if commands.is_empty() {
        return None;
    }
    let i1 = format!("{indent}  ");
    let i2 = format!("{indent}    ");
    let mut out = format!("{indent}<FirstLogonCommands>\n");
    for (n, c) in commands.iter().enumerate() {
        let order = n + 1;
        out.push_str(&format!("{i1}<SynchronousCommand wcm:action=\"add\">\n"));
        out.push_str(&format!("{i2}<Order>{order}</Order>\n"));
        out.push_str(&format!("{i2}<CommandLine>{}</CommandLine>\n", xml::escape(c)));
        let description = descriptions
            .get(n)
            .cloned()
            .flatten()
            .unwrap_or_else(|| format!("Step {order}"));
        out.push_str(&format!(
            "{i2}<Description>{}</Description>\n",
            xml::escape(&description)
        ));
        out.push_str(&format!("{i2}<RequiresUserInput>false</RequiresUserInput>\n"));
        out.push_str(&format!("{i1}</SynchronousCommand>\n"));
    }
    out.push_str(&format!("{indent}</FirstLogonCommands>"));
    Some(out)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;
    use crate::catalog::install::SAMPLE_ONE_TIME;

    fn messages(problems: &[ConfigProblem]) -> String {
        problems
            .iter()
            .map(|p| p.message.clone())
            .collect::<Vec<_>>()
            .join(" | ")
    }

    fn file(password: &str) -> String {
        format!(
            r#"<?xml version="1.0" encoding="utf-8"?>
<unattend xmlns="urn:schemas-microsoft-com:unattend" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State">
  <settings pass="windowsPE">
    <component name="Microsoft-Windows-International-Core-WinPE" processorArchitecture="amd64">
      <UILanguage>en-US</UILanguage>
    </component>
    <component name="Microsoft-Windows-Setup" processorArchitecture="amd64">
      <DiskConfiguration>
        <Disk wcm:action="add">
          <DiskID>0</DiskID>
          <CreatePartitions>
            <CreatePartition wcm:action="add"><Order>1</Order><Type>EFI</Type><Size>260</Size></CreatePartition>
            <CreatePartition wcm:action="add"><Order>2</Order><Type>MSR</Type><Size>16</Size></CreatePartition>
            <CreatePartition wcm:action="add"><Order>3</Order><Type>Primary</Type><Extend>true</Extend></CreatePartition>
          </CreatePartitions>
        </Disk>
      </DiskConfiguration>
      <ImageInstall><OSImage><InstallFrom><MetaData wcm:action="add"><Key>/IMAGE/NAME</Key><Value>Windows Server 2022 SERVERSTANDARD</Value></MetaData></InstallFrom><InstallTo><DiskID>0</DiskID><PartitionID>3</PartitionID></InstallTo></OSImage></ImageInstall>
      <UserData><AcceptEula>true</AcceptEula></UserData>
    </component>
  </settings>
  <settings pass="specialize">
    <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64">
      <ComputerName>vm-1</ComputerName>
    </component>
  </settings>
  <settings pass="oobeSystem">
    <component name="Microsoft-Windows-International-Core" processorArchitecture="amd64">
      <InputLocale>en-US</InputLocale>
      <UserLocale>en-US</UserLocale>
    </component>
    <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64">
      <OOBE><HideEULAPage>true</HideEULAPage></OOBE>
      <UserAccounts>
        <AdministratorPassword><Value>{password}</Value><PlainText>true</PlainText></AdministratorPassword>
      </UserAccounts>
      <TimeZone>UTC</TimeZone>
      <FirstLogonCommands>
        <SynchronousCommand wcm:action="add">
          <Order>1</Order>
          <CommandLine>powershell -Command "winrm quickconfig -transport:https"</CommandLine>
          <Description>WinRM over HTTPS</Description>
        </SynchronousCommand>
      </FirstLogonCommands>
    </component>
  </settings>
</unattend>
"#
        )
    }

    #[test]
    fn a_good_answer_file_passes() {
        let problems = check(&file(SAMPLE_ONE_TIME));
        assert!(problems.is_empty(), "{problems:?}");
        assert_eq!(disk_need_mb(&file(SAMPLE_ONE_TIME)), Some(276));
    }

    #[test]
    fn mistakes_secrets_and_what_setup_would_ask() {
        assert!(messages(&check("<unattend><settings pass=\"x\"></unattend>")).contains("well-formed"));
        assert!(messages(&check("<answers/>")).contains("an answer file's is <unattend>"));
        let text = messages(&check("<unattend><settings pass=\"later\"/></unattend>"));
        for want in [
            "xmlns",
            "isn't a Setup pass",
            "No Microsoft-Windows-Setup",
            "No account",
            "first-start questions",
            "WinRM over HTTPS isn't turned on",
        ] {
            assert!(text.contains(want), "{want}: {text}");
        }
        let plain = check(&file("letmein"));
        assert!(
            plain
                .iter()
                .any(|p| p.blocks_saving && p.message.contains("holds a password")),
            "{plain:?}"
        );
        let not_plain = file(SAMPLE_ONE_TIME).replace("<PlainText>true", "<PlainText>false");
        assert!(messages(&check(&not_plain)).contains("PlainText has to be true"));
        let key = file(SAMPLE_ONE_TIME).replace(
            "<AcceptEula>",
            "<ProductKey><Key>XXXXX-XXXXX</Key></ProductKey><AcceptEula>",
        );
        assert!(messages(&check(&key)).contains("product key"));
    }

    #[test]
    fn the_form_changes_single_elements() {
        let body = file("{{password.admin}}").replace("<ComputerName>vm-1", "<ComputerName>{{hostname}}");
        let read = read_form(&body);
        assert_eq!(read.unreadable, None);
        let form = read.form.clone();
        assert_eq!(form.hostname.as_deref(), Some("{{hostname}}"));
        assert_eq!(form.timezone.as_deref(), Some("UTC"));
        assert_eq!(form.locale.as_deref(), Some("en-US"));
        assert_eq!(form.users[0].password.as_deref(), Some("{{password.admin}}"));
        assert_eq!(
            form.late_commands,
            ["powershell -Command \"winrm quickconfig -transport:https\""]
        );
        let mut after = form.clone();
        after.timezone = Some("W. Europe Standard Time".into());
        after.locale = Some("de-DE".into());
        after.late_commands.push("cmd /c echo two & echo three".into());
        let changed = crate::catalog::install::changed_fields(&form, &after);
        let out = apply_form(&body, &form, &after, &changed).unwrap();
        assert!(out.contains("<TimeZone>W. Europe Standard Time</TimeZone>"), "{out}");
        assert!(
            out.contains("      <InputLocale>en-US</InputLocale>\n      <UserLocale>de-DE</UserLocale>\n"),
            "{out}"
        );
        assert!(
            !out.contains("<SystemLocale>de-DE"),
            "only the locales the file sets: {out}"
        );
        assert!(out.contains("<Description>WinRM over HTTPS</Description>"), "{out}");
        assert!(
            out.contains("<CommandLine>cmd /c echo two &amp; echo three</CommandLine>"),
            "{out}"
        );
        assert!(out.contains("<Order>2</Order>"), "{out}");
        assert!(
            out.contains("<ComputerName>{{hostname}}</ComputerName>"),
            "untouched: {out}"
        );
        let back = read_form(&out).form;
        assert_eq!(back.late_commands, after.late_commands);
        assert_eq!(back.timezone, after.timezone);
        assert_eq!(back.locale, after.locale);
        let no_users = InstallForm {
            users: vec![UserForm {
                name: "bob".into(),
                ..UserForm::default()
            }],
            ..form.clone()
        };
        assert!(apply_form(&body, &form, &no_users, &[FormField::Users]).is_err());
    }
}
