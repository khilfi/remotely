//! S2 ("a2"): Debian's installer ISOs (12.15 and 13.7, netinst and DVD-1 seen). BIOS boots isolinux and UEFI
//! (Secure Boot too) reads `/boot/grub/grub.cfg`, so both files are replaced whole by a one-entry menu that boots
//! the text installer at once ([`isolinux_cfg`], [`grub_cfg`]). Its `preseed/early_command` ([`EARLY_COMMAND`])
//! runs before the first menu step: it finds the CD that holds `preseed.cfg` (the seed, by content, any label),
//! copies it to `/tmp`, and drops that drive from the guest's kernel, since apt-cdrom stops the install at
//! "Configure the package manager" while a second CD is there. `preseed/file=/tmp/preseed.cfg` then loads it as
//! any preseed, and the guard at its start keeps the second run (file-preseed runs it again) from doing anything.
//! The copy holds nothing of any VM, so one copy serves every VM of an ISO.
//!
//! In GRUB the command's word is single-quoted, since GRUB expands `$` and splits at `;`; GRUB hands it on in
//! double quotes, which the kernel strips, as isolinux's `"..."` are.

use std::io::{Read, Seek};

use super::linux::{md5_words, LinuxIso};
use super::{unexpected, Flavor, Image, IsoWrite};
use crate::error::Result;

pub const ISOLINUX_CFG: &str = "/isolinux/isolinux.cfg";
pub const GRUB_CFG: &str = "/boot/grub/grub.cfg";
pub const KERNEL: &str = "/install.amd/vmlinuz";
/// The text installer's initrd, whose UI runs on the serial console.
pub const INITRD: &str = "/install.amd/initrd.gz";
/// The installer's own words before the command: no question below critical, the preseed from where the command
/// copies it.
pub const INSTALLER_WORDS: &str = "auto=true priority=critical preseed/file=/tmp/preseed.cfg";
/// Finds the seed's `preseed.cfg` on any CD drive (30 tries a second apart), copies it to `/tmp`, unmounts, and
/// drops that drive from the kernel. Holds no `'` (GRUB's quotes) and no `"` (the kernel's).
pub const EARLY_COMMAND: &str = "[ -e /tmp/preseed.cfg ] && exit 0; modprobe ahci; modprobe sr_mod; modprobe isofs; \
mkdir -p /seed; n=0; while [ $n -lt 30 ]; do for d in /dev/sr0 /dev/sr1 /dev/sr2 /dev/sr3; do mount -t iso9660 -o ro \
$d /seed 2>/dev/null && { [ -e /seed/preseed.cfg ] && break 2; umount /seed; }; done; n=$((n+1)); sleep 1; done; \
cp /seed/preseed.cfg /tmp/preseed.cfg; umount /seed; echo 1 > /sys/block/${d#/dev/}/device/delete";
/// The serial console, last before `---` so the installer's UI is on the port.
pub const SERIAL_WORDS: &str = "console=tty0 console=ttyS0,115200n8";
/// After `---`: copied to the installed system's command line.
pub const AFTER_DASHES: &str = "quiet console=tty0 console=ttyS0,115200n8";
/// Debian's menu files are a few KB on the ISOs seen.
const MAX_MENU_BYTES: u64 = 64 * 1024;

/// The words before `---` as isolinux passes them.
pub fn isolinux_words() -> String {
    format!("{INSTALLER_WORDS} preseed/early_command=\"{EARLY_COMMAND}\" {SERIAL_WORDS}")
}

/// The words before `---` as GRUB reads them: the command's word in single quotes.
pub fn grub_words() -> String {
    format!("{INSTALLER_WORDS} 'preseed/early_command={EARLY_COMMAND}' {SERIAL_WORDS}")
}

/// The new `/isolinux/isolinux.cfg`: a `default` label with `prompt 0` and no `ui` boots at once, no menu.
pub fn isolinux_cfg() -> String {
    format!(
        "path \ndefault unattended\nprompt 0\ntimeout 0\nlabel unattended\n\tkernel {KERNEL}\n\tappend {} \
         initrd={INITRD} --- {AFTER_DASHES}\n",
        isolinux_words()
    )
}

/// The new `/boot/grub/grub.cfg`: one entry, no wait.
pub fn grub_cfg() -> String {
    format!(
        "set timeout=0\nset default=0\nmenuentry 'Unattended install' {{\n    linux {KERNEL} {} --- \
         {AFTER_DASHES}\n    initrd {INITRD}\n}}\n",
        grub_words()
    )
}

pub(crate) fn plan<R: Read + Seek>(image: &mut Image<R>) -> Result<(Vec<IsoWrite>, Vec<String>)> {
    let flavor = Flavor::Debian;
    let iso = LinuxIso::open(image, flavor)?;
    iso.require_file(image, KERNEL)?;
    iso.require_file(image, INITRD)?;
    let isolinux = iso.text_file(image, ISOLINUX_CFG, MAX_MENU_BYTES)?;
    let grub = iso.text_file(image, GRUB_CFG, MAX_MENU_BYTES)?;
    iso.check_alone(image, &[&isolinux, &grub])?;
    let new_isolinux = isolinux_cfg();
    let new_grub = grub_cfg();
    if !std::str::from_utf8(&grub.content).is_ok_and(|text| text.contains(KERNEL)) {
        return Err(unexpected(flavor, format!("its {GRUB_CFG} doesn't boot {KERNEL}")));
    }
    let already = isolinux.content == new_isolinux.as_bytes() && grub.content == new_grub.as_bytes();
    let mut writes = isolinux.rewrite(image, new_isolinux.as_bytes(), flavor)?;
    writes.extend(grub.rewrite(image, new_grub.as_bytes(), flavor)?);
    let md5 = iso.md5_update(
        image,
        &[
            ("./boot/grub/grub.cfg", new_grub.as_bytes()),
            ("./isolinux/isolinux.cfg", new_isolinux.as_bytes()),
        ],
    )?;
    writes.extend(md5.writes.iter().cloned());
    let release = iso.release(image)?;
    let mut summary = vec![
        match release {
            Some(release) => format!("Release: {release}."),
            None => "Release: not named on the ISO (no /.disk/info).".to_owned(),
        },
        "isolinux.cfg (BIOS): replaced by one entry that starts the unattended install at once.".to_owned(),
        "grub.cfg (UEFI): replaced by the same entry, with no wait.".to_owned(),
        md5_words(&md5, 0, grub.name()),
    ];
    if md5.lines.get(1).copied().unwrap_or(0) > 0 {
        summary.push(md5_words(&md5, 1, isolinux.name()));
    }
    if already {
        summary.push("The ISO already had these menus: it is a copy Remotely made.".to_owned());
    }
    Ok((writes, summary))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_command_survives_both_quotings() {
        assert!(!EARLY_COMMAND.contains('\''), "GRUB's single quotes");
        assert!(!EARLY_COMMAND.contains('"'), "the kernel's double quotes");
        assert!(EARLY_COMMAND.starts_with("[ -e /tmp/preseed.cfg ] && exit 0; "));
        assert!(EARLY_COMMAND.ends_with("echo 1 > /sys/block/${d#/dev/}/device/delete"));
        assert!(!EARLY_COMMAND.contains("  "), "no doubled spaces from the line breaks");
    }

    #[test]
    fn the_menus_are_s2s_lines() {
        let isolinux = isolinux_cfg();
        let lines: Vec<&str> = isolinux.lines().collect();
        assert_eq!(
            lines[..6],
            [
                "path ",
                "default unattended",
                "prompt 0",
                "timeout 0",
                "label unattended",
                "\tkernel /install.amd/vmlinuz"
            ]
        );
        assert_eq!(
            lines[6],
            format!(
                "\tappend auto=true priority=critical preseed/file=/tmp/preseed.cfg \
                 preseed/early_command=\"{EARLY_COMMAND}\" console=tty0 console=ttyS0,115200n8 \
                 initrd=/install.amd/initrd.gz --- quiet console=tty0 console=ttyS0,115200n8"
            )
        );
        assert_eq!(lines.len(), 7);
        let grub = grub_cfg();
        let lines: Vec<&str> = grub.lines().collect();
        assert_eq!(
            lines[..3],
            ["set timeout=0", "set default=0", "menuentry 'Unattended install' {"]
        );
        assert_eq!(
            lines[3],
            format!(
                "    linux /install.amd/vmlinuz auto=true priority=critical preseed/file=/tmp/preseed.cfg \
                 'preseed/early_command={EARLY_COMMAND}' console=tty0 console=ttyS0,115200n8 --- quiet console=tty0 \
                 console=ttyS0,115200n8"
            )
        );
        assert_eq!(lines[4..], ["    initrd /install.amd/initrd.gz", "}"]);
        assert!(isolinux.ends_with('\n') && grub.ends_with('\n'));
        // Each fits the one sector isolinux.cfg has on the ISOs seen.
        assert_eq!((isolinux.len(), grub.len()), (703, 703));
    }
}
