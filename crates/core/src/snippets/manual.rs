//! QL-13: each library command's official manual page, and the only sites the app opens.
//!
//! A [`Manual`] names a page on one of the documentation sites in [`MANUAL_HOSTS`]: the Linux
//! man-pages project's man7.org for standard commands, freedesktop.org for systemd's tools, a
//! project's own documentation for tools such as Docker, kubectl, nginx or chrony, and Debian's or
//! Ubuntu's manual pages where a project has no page of its own.
//!
//! [`checked`] is the gate the desktop shell opens a link through: an https address on one of those
//! hosts, nothing else, so the UI can't make the app open any other address. Opening a page changes
//! nothing, so it is not audited and the read-only lock (FD-03) doesn't stop it.

use url::{Host, Url};

use crate::error::{CoreError, Result};

/// Where a command's manual page is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Manual {
    /// The man-pages project's site (man7.org): a page and its section, such as `df` and `1`.
    Man7 { page: &'static str, section: &'static str },
    /// systemd's manual on freedesktop.org, by page: `systemctl`, `timesyncd.conf`.
    Systemd(&'static str),
    /// Debian 12's manual pages, for tools whose project has no page of its own.
    Debian {
        package: &'static str,
        page: &'static str,
        section: &'static str,
    },
    /// Docker's CLI reference, by path: `container/ls`.
    Docker(&'static str),
    /// kubectl's reference, by path: `kubectl_get`, `kubectl_config/kubectl_config_view`.
    Kubectl(&'static str),
    /// Podman's manual, by command: `ps`, `pod-ps`.
    Podman(&'static str),
    /// Helm's reference, by command: `list`, `get_values`.
    Helm(&'static str),
    /// OpenSSL 3.0's manual (the version RHEL 9, Ubuntu 22.04 and Debian 12 ship), by command.
    Openssl(&'static str),
    /// Any other page: a full https address on one of [`MANUAL_HOSTS`].
    Web(&'static str),
}

/// A page of the man-pages project: `man("df", "1")`.
pub const fn man(page: &'static str, section: &'static str) -> Manual {
    Manual::Man7 { page, section }
}

/// A page of systemd's manual: `sd("systemctl")`.
pub const fn sd(page: &'static str) -> Manual {
    Manual::Systemd(page)
}

/// A Debian manual page: `deb("open-iscsi", "iscsiadm", "8")`.
pub const fn deb(package: &'static str, page: &'static str, section: &'static str) -> Manual {
    Manual::Debian { package, page, section }
}

pub const fn docker(path: &'static str) -> Manual {
    Manual::Docker(path)
}

pub const fn kubectl(path: &'static str) -> Manual {
    Manual::Kubectl(path)
}

pub const fn podman(command: &'static str) -> Manual {
    Manual::Podman(command)
}

pub const fn helm(command: &'static str) -> Manual {
    Manual::Helm(command)
}

pub const fn openssl(command: &'static str) -> Manual {
    Manual::Openssl(command)
}

pub const fn web(url: &'static str) -> Manual {
    Manual::Web(url)
}

impl Manual {
    /// The page's address.
    pub fn url(&self) -> String {
        match *self {
            Manual::Man7 { page, section } => {
                // The folder is the section's number: `man1` for `1`, and for `1p` too.
                let folder: String = section.chars().take_while(char::is_ascii_digit).collect();
                format!("https://man7.org/linux/man-pages/man{folder}/{page}.{section}.html")
            }
            Manual::Systemd(page) => format!("https://www.freedesktop.org/software/systemd/man/latest/{page}.html"),
            Manual::Debian { package, page, section } => {
                format!("https://manpages.debian.org/bookworm/{package}/{page}.{section}.en.html")
            }
            Manual::Docker(path) => format!("https://docs.docker.com/reference/cli/docker/{path}/"),
            Manual::Kubectl(path) => format!("https://kubernetes.io/docs/reference/kubectl/generated/{path}/"),
            Manual::Podman(command) => format!("https://docs.podman.io/en/latest/markdown/podman-{command}.1.html"),
            Manual::Helm(command) => format!("https://helm.sh/docs/helm/helm_{command}/"),
            Manual::Openssl(command) => format!("https://docs.openssl.org/3.0/man1/openssl-{command}/"),
            Manual::Web(url) => url.to_owned(),
        }
    }
}

/// The documentation sites a manual link may open, exactly as named (no other subdomain).
pub const MANUAL_HOSTS: &[&str] = &[
    "man7.org",
    "www.freedesktop.org",
    "manpages.debian.org",
    "manpages.ubuntu.com",
    "docs.docker.com",
    "docs.podman.io",
    "kubernetes.io",
    "helm.sh",
    "docs.openssl.org",
    "nginx.org",
    "httpd.apache.org",
    "dev.mysql.com",
    "www.postgresql.org",
    "chrony-project.org",
    "firewalld.org",
    "download.samba.org",
    "dnf.readthedocs.io",
    "docs.kernel.org",
];

/// `url` when it is a manual page the app may open: https, on one of [`MANUAL_HOSTS`], on the usual
/// port, with no user name or password in it. Anything else is refused, so a link can only ever open
/// documentation.
pub fn checked(url: &str) -> Result<Url> {
    let refused =
        || CoreError::InvalidInput("Remotely opens only manual pages on its list of documentation sites.".into());
    let parsed = Url::parse(url.trim()).map_err(|_| refused())?;
    let allowed_host = match parsed.host() {
        Some(Host::Domain(host)) => MANUAL_HOSTS.contains(&host),
        _ => false,
    };
    // `port()` is None for https's own port 443, written or not.
    if parsed.scheme() != "https"
        || !allowed_host
        || parsed.port().is_some()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
    {
        return Err(refused());
    }
    Ok(parsed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_kind_of_page_has_its_address() {
        assert_eq!(man("df", "1").url(), "https://man7.org/linux/man-pages/man1/df.1.html");
        assert_eq!(
            man("proc_meminfo", "5").url(),
            "https://man7.org/linux/man-pages/man5/proc_meminfo.5.html"
        );
        assert_eq!(
            man("cat", "1p").url(),
            "https://man7.org/linux/man-pages/man1/cat.1p.html"
        );
        assert_eq!(
            sd("systemctl").url(),
            "https://www.freedesktop.org/software/systemd/man/latest/systemctl.html"
        );
        assert_eq!(
            deb("open-iscsi", "iscsiadm", "8").url(),
            "https://manpages.debian.org/bookworm/open-iscsi/iscsiadm.8.en.html"
        );
        assert_eq!(
            docker("container/ls").url(),
            "https://docs.docker.com/reference/cli/docker/container/ls/"
        );
        assert_eq!(
            kubectl("kubectl_config/kubectl_config_view").url(),
            "https://kubernetes.io/docs/reference/kubectl/generated/kubectl_config/kubectl_config_view/"
        );
        assert_eq!(
            podman("pod-ps").url(),
            "https://docs.podman.io/en/latest/markdown/podman-pod-ps.1.html"
        );
        assert_eq!(helm("get_values").url(), "https://helm.sh/docs/helm/helm_get_values/");
        assert_eq!(openssl("x509").url(), "https://docs.openssl.org/3.0/man1/openssl-x509/");
        assert_eq!(
            web("https://nginx.org/en/docs/switches.html").url(),
            "https://nginx.org/en/docs/switches.html"
        );
    }

    #[test]
    fn manual_pages_on_the_listed_sites_open() {
        for url in [
            "https://man7.org/linux/man-pages/man1/df.1.html",
            "https://www.freedesktop.org/software/systemd/man/latest/systemctl.html",
            "https://manpages.debian.org/bookworm/open-iscsi/iscsiadm.8.en.html",
            "https://nginx.org/en/docs/switches.html#reload",
            "https://MAN7.org/linux/man-pages/man1/df.1.html",
            "https://man7.org:443/linux/man-pages/man1/df.1.html",
        ] {
            assert!(checked(url).is_ok(), "{url}");
        }
    }

    #[test]
    fn anything_else_is_refused() {
        for url in [
            // Not https.
            "http://man7.org/linux/man-pages/man1/df.1.html",
            "file:///C:/Windows/System32/calc.exe",
            "ftp://man7.org/df.1.html",
            "javascript:alert(1)",
            // Another host, a lookalike, a subdomain or a parent domain.
            "https://example.com/",
            "https://man7.org.example.com/df.1.html",
            "https://evilman7.org/",
            "https://www.man7.org/linux/man-pages/man1/df.1.html",
            "https://freedesktop.org/software/systemd/man/latest/systemctl.html",
            "https://debian.org/",
            "https://man7.org./linux/man-pages/man1/df.1.html",
            // The allowed host as a user name, or with credentials, or on another port.
            "https://man7.org@example.com/",
            "https://alice:secret@man7.org/",
            "https://alice@man7.org/",
            "https://man7.org:8443/",
            "https://evil.test\\@man7.org/",
            // Addresses and nothing.
            "https://192.0.2.10/",
            "https://[2001:db8::1]/",
            "",
            "man7.org/linux/man-pages/man1/df.1.html",
        ] {
            let err = checked(url).expect_err(url);
            assert_eq!(err.code(), "invalid_input", "{url}");
        }
    }
}
