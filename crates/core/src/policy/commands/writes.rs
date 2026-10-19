//! BX-06: forms of read-only commands that change something.
//!
//! A read-only entry matches a command's first words, so "ip link" also matches
//! `ip link set eth0 down` and "journalctl" matches `journalctl --vacuum-size=100M`. [`writes`] runs
//! after that match and makes such forms "other" again. It is code, not one of the editable rules, so
//! it also covers lists saved before it existed and entries users added themselves.
//!
//! Where a command has a short list of forms that only read (ip, the systemd tools, env, firewall-cmd)
//! anything else writes. Elsewhere the options and arguments that write are named, and a word holding
//! `$` writes too: at run time it can expand to any option.
//!
//! The environment a command runs with counts too. [`harmless_assignment`] says which `NAME=value`
//! settings, in front of a command or given to `env`, leave it read-only; [`env_command`] finds the
//! command `env` runs so that it is classified like any other.

use std::iter::Peekable;

use super::is_assignment;

/// True when `words` (a command and its arguments, as the shell splits them) is a known writing
/// form of a command whose usual forms only read.
pub(super) fn writes(words: &[String]) -> bool {
    let Some((command, args)) = words.split_first() else {
        return false;
    };
    let expands = args.iter().any(|a| a.contains('$'));
    let parse = |values, optional, long_values| {
        Spec {
            values,
            optional,
            long_values,
        }
        .parse(args)
    };
    // `/usr/sbin/ip` is `ip`.
    match command.rsplit('/').next().unwrap_or(command) {
        "ip" => ip_writes(args),
        "systemctl" => {
            let p = parse("tspPHMnoC", "", SYSTEMCTL_VALUES);
            !p.operands.first().is_none_or(|verb| SYSTEMCTL_READS.contains(verb))
        }
        "timedatectl" => {
            let p = parse("HMp", "", &["host", "machine", "property"]);
            !p.operands.first().is_none_or(|verb| TIMEDATECTL_READS.contains(verb))
        }
        "hostnamectl" => {
            // `hostnamectl hostname` shows the name; `hostnamectl hostname web02` sets it.
            let p = parse("HM", "", &["host", "machine", "json"]);
            !matches!(
                p.operands.as_slice(),
                [] | ["status" | "help", ..] | ["hostname" | "icon-name" | "chassis" | "deployment" | "location"]
            )
        }
        "env" => {
            // Shows the environment. A command it runs only gets here when `env_command` would not
            // take it apart (another option, a variable that isn't harmless), so it writes.
            let p = parse("uC", "", &["unset", "chdir"]);
            expands
                || p.has_short("S")
                || p.has_long(&["split-string"])
                || p.operands.iter().any(|w| *w != "-" && !harmless_assignment(w))
        }
        "journalctl" => {
            // `--cursor` reads; `--cursor-file` saves the last cursor in a file.
            let p = parse("", "", &[]);
            expands || p.long.iter().any(|n| *n != "cursor" && prefix_of(n, JOURNALCTL_WRITES))
        }
        "dmesg" => {
            let p = parse("FfKlns", "L", &[]);
            expands
                || p.has_short("cCDEn")
                || p.has_long(&["clear", "read-clear", "console-off", "console-on", "console-level"])
        }
        "date" => {
            // An operand other than `+FORMAT` sets the clock (`date 101912002026`).
            let p = parse("dfrs", "I", &["date", "file", "reference", "set", "rfc-3339"]);
            expands || p.has_short("s") || p.has_long(&["set"]) || p.operands.iter().any(|o| !o.starts_with('+'))
        }
        "hostname" => {
            // Any operand is the new name.
            let p = parse("F", "", &["file"]);
            expands || p.has_short("bF") || p.has_long(&["boot", "file"]) || !p.operands.is_empty()
        }
        "ss" => {
            // -K closes sockets; -D dumps them into a file.
            let p = parse("fADFN", "", &[]);
            expands || p.has_short("KD") || p.has_long(&["kill", "diag"])
        }
        "sort" => {
            // --compress-program runs a program.
            let p = parse("kSoTt", "", &[]);
            expands || p.has_short("o") || p.has_long(&["output", "compress-program"])
        }
        "uniq" => {
            // `uniq INPUT OUTPUT` writes OUTPUT.
            let p = parse("fsw", "", &["skip-fields", "skip-chars", "check-chars"]);
            expands || p.operands.len() > 1
        }
        "less" => {
            let p = parse("bhjkoOpPtTxyz#", "", &[]);
            expands || p.has_short("oO") || p.has_long(&["log-file", "LOG-FILE"])
        }
        "file" => {
            // -C compiles a magic file into the current folder.
            let p = parse("eFfmP", "", &[]);
            expands || p.has_short("C") || p.has_long(&["compile"])
        }
        "rpm" => {
            // --pipe runs a shell command; macros (--eval, --define, macro and spec files) can too.
            let p = parse("", "", &[]);
            expands
                || p.has_short("DE")
                || p.has_long(&["pipe", "eval", "define", "macros", "load", "rcfile", "specfile"])
        }
        "iptables" | "ip6tables" | "iptables-legacy" | "ip6tables-legacy" | "iptables-nft" | "ip6tables-nft" => {
            // `iptables -L -Z` lists the rules and zeroes their counters.
            let p = parse("", "", &[]);
            expands || p.has_short("Z") || p.has_long(&["zero"])
        }
        "nft" => {
            // Only `list`/`describe` read. -f/-I run or include a file, and a `;` or newline inside an
            // argument (quoting, `$'…\n…'`) packs extra statements such as `flush ruleset` into one call.
            let p = parse("fI", "", &["file", "includepath"]);
            expands
                || p.has_short("fI")
                || p.has_long(&["file", "includepath"])
                || args.iter().any(|a| a.contains(';') || a.contains('\n'))
                || !matches!(p.operands.first().copied(), Some("list" | "describe"))
        }
        "smartctl" => {
            // Reads health, attributes and logs (-H, -a, -A, -x, -i, -l, ...). Writes to the device
            // when it starts or aborts a self-test (-t, -X), or sets a feature (-s, -o, -S on/off).
            let p = parse("", "", &[]);
            expands || p.has_short("stXoS") || p.has_long(&["test", "abort", "set", "smart", "offlineauto", "saveauto"])
        }
        "sysctl" => {
            // Reads a parameter (`sysctl -a`, `sysctl net.ipv4.ip_forward`); writes one with `-w`, a
            // `name=value` operand, or by loading a file (`-p`/`-f`, --load, --system).
            let p = parse("", "", &[]);
            expands
                || p.has_short("wpf")
                || p.has_long(&["write", "load", "system", "files"])
                || p.operands.iter().any(|o| o.contains('='))
        }
        "openssl" => {
            // openssl takes `-opt`, `--opt` and `-opt=value` (apps/lib/opt.c), so each word is compared
            // on its bare name. An allow-list of read subcommands: version, x509, s_client, verify, crl,
            // ciphers, list always read; req/rsa/pkey/ec/dsa and the param tools only with
            // -noout/-check/-text and no key generation. Any file-writing option writes.
            let sub = args.first().map(|a| bare_opt(a)).unwrap_or("");
            let flag = |a: &String| a.starts_with('-');
            let file_opt = args.iter().filter(|a| flag(a)).any(|a| {
                matches!(
                    bare_opt(a),
                    "out"
                        | "keyout"
                        | "CAout"
                        | "CAkeyout"
                        | "signkey"
                        | "outfile"
                        | "sess_out"
                        | "keylogfile"
                        | "writerand"
                        | "respout"
                        | "reqout"
                        | "CAserial"
                        | "CAcreateserial"
                )
            });
            // Skip the subcommand so the `x509` command is not read as the `-x509` option.
            let generates = args
                .iter()
                .skip(1)
                .filter(|a| flag(a))
                .any(|a| matches!(bare_opt(a), "new" | "newkey" | "x509" | "genkey"));
            let read_sub = match sub {
                "version" | "x509" | "verify" | "crl" | "ciphers" | "list" | "s_client" | "errstr" | "asn1parse" => {
                    true
                }
                "req" | "rsa" | "pkey" | "ec" | "dsa" | "ecparam" | "dsaparam" | "pkeyparam" => args
                    .iter()
                    .filter(|a| flag(a))
                    .any(|a| matches!(bare_opt(a), "noout" | "check" | "text")),
                _ => false,
            };
            expands || file_opt || generates || !read_sub
        }
        "firewall-cmd" => firewall_cmd_writes(args),
        "kubectl" => {
            let has = |w: &str| args.iter().any(|a| a == w);
            // `kubectl cluster-info dump --output-directory DIR` writes files.
            let dump = has("cluster-info")
                && has("dump")
                && (expands || args.iter().any(|a| a.starts_with("--output-directory")));
            // `kubectl config view --raw` prints cluster credentials; plain `config view` redacts them.
            let raw = has("config") && has("view") && args.iter().any(|a| a == "--raw" || a.starts_with("--raw="));
            dump || raw
        }
        "mysqladmin" => {
            // Several commands run in one call (`mysqladmin status shutdown`), so every command word
            // must read; option values (-u alice, -h db, -P 3306, -p[pass]) are skipped.
            const READS: &[&str] = &[
                "status",
                "ping",
                "processlist",
                "variables",
                "extended-status",
                "version",
            ];
            let p = parse(
                "uhPSic",
                "pw",
                &[
                    "user",
                    "host",
                    "port",
                    "socket",
                    "sleep",
                    "count",
                    "default-character-set",
                    "protocol",
                ],
            );
            expands || p.operands.iter().any(|o| !READS.contains(o))
        }
        "mysql" | "mariadb" => {
            // The read entry is just --version; -e/--execute runs arbitrary SQL (also when attached,
            // `-eSELECT`, or clustered). Other value options are declared so clusters parse right.
            let p = parse(
                "ehPDuS",
                "p",
                &["execute", "host", "port", "database", "user", "socket"],
            );
            expands || p.has_short("e") || p.has_long(&["execute"])
        }
        "psql" => {
            // The read entry is just --version; -c/-f run SQL or a script file, and -o/-L write output
            // or a log file.
            let p = parse(
                "cfdhpUoLvPFRT",
                "wW",
                &["command", "file", "output", "log-file", "dbname", "host", "username"],
            );
            expands || p.has_short("cfoL") || p.has_long(&["command", "file", "output", "log-file"])
        }
        "auditctl" => {
            // Only -l (list), -s (status), -v (version) read; every other option changes the config,
            // and options apply in order (`auditctl -l -D` lists then deletes every rule).
            let p = parse("", "", &[]);
            expands
                || !p.short.iter().all(|&c| matches!(c, 'l' | 's' | 'v' | 'h'))
                || !p.long.is_empty()
                || !p.operands.is_empty()
        }
        "multipath" => {
            // -l/-ll show; the last action option wins, so `multipath -ll -F` flushes every map. Only
            // -l and -v (verbosity) are safe.
            let p = parse("v", "", &[]);
            expands || !p.short.iter().all(|&c| matches!(c, 'l' | 'v')) || !p.long.is_empty() || !p.operands.is_empty()
        }
        "swapon" => {
            // --show/-s display; -a/--all and a device operand enable swap.
            let p = parse("LUpo", "", &["priority", "label", "uuid"]);
            let shows = p.has_short("s") || p.long.iter().any(|n| prefix_of(n, &["show", "summary"]));
            expands || !shows || p.has_short("a") || p.has_long(&["all"]) || !p.operands.is_empty()
        }
        "chronyc" => {
            // `-m` runs several commands in one call (`chronyc -m tracking makestep`, or clustered
            // `-nm`); without it only the one read command named by the entry runs. -f/-h/-p take values.
            let p = parse("fhp", "", &[]);
            expands || p.has_short("m")
        }
        "ntpq" => {
            // `-c` runs an ntpq command, which can write (`writevar`, `:config`), attached or clustered;
            // the read entry uses none.
            let p = parse("c", "", &["command"]);
            expands || p.has_short("c") || p.has_long(&["command"])
        }
        "crontab" => {
            // `-l` lists; `-r`/`-e`/`-i` remove or edit, and a file operand installs a new crontab.
            let p = parse("u", "", &["user"]);
            expands || p.short.iter().any(|&c| matches!(c, 'r' | 'e' | 'i')) || !p.operands.is_empty()
        }
        "hwclock" => {
            // --show/-r read the RTC; -w/--systohc, -s/--hctosys, -a/--adjust, --set change a clock.
            // getopt_long, so abbreviations (`--sys`) and clusters count; --date takes a value.
            let p = parse("f", "", &["date"]);
            expands
                || p.has_short("wsa")
                || p.has_long(&["systohc", "hctosys", "set", "adjust", "setepoch", "param-set"])
        }
        "nginx" => {
            // -t/-T/-v/-V test or print; -s sends a signal (reload/stop/quit), attached or clustered
            // (`-ts stop`). -s/-c/-g/-p/-e take values.
            let p = parse("scgpe", "", &[]);
            expands || p.has_short("s")
        }
        "apachectl" | "apache2ctl" | "httpd" | "apache2" => {
            // configtest/-t/-S/-M/-v inspect; -k ACTION controls the server (attached/clustered too),
            // as does a start/stop/restart/graceful word. Value options are declared so -k parses.
            let p = parse("CcdDeEfkn", "", &[]);
            expands
                || p.has_short("k")
                || p.operands.iter().any(|o| {
                    matches!(
                        *o,
                        "start" | "stop" | "restart" | "graceful" | "graceful-stop" | "startssl"
                    )
                })
        }
        "nfsstat" => {
            // -z/--zero resets the counters (attached/clustered, e.g. `-sz`). -o takes a type value.
            let p = parse("o", "", &["zero"]);
            expands || p.has_short("z") || p.has_long(&["zero"])
        }
        "ausearch" => {
            // --checkpoint FILE (or =FILE, or the abbreviation --check) writes a checkpoint file.
            let p = parse("", "", &["checkpoint"]);
            expands || p.has_long(&["checkpoint"])
        }
        "lshw" => expands || args.iter().any(|a| a.starts_with('-') && bare_opt(a) == "dump"),
        "sshd" => {
            // -E FILE appends a log (attached `-E/tmp/log`, or clustered `-tE /tmp/log`). The value
            // options are declared so clusters and attached values parse right.
            let p = parse("bCEfghopu", "", &[]);
            expands || p.has_short("E")
        }
        "apt-cache" => expands || args.iter().any(|a| a == "gencaches"),
        _ => false,
    }
}

/// True when `word` is a `NAME=value` setting that leaves a read-only command read-only, whether it
/// stands in front of the command (`LC_ALL=C sort`), is given to `env` (`env TZ=UTC date`) or stands
/// alone (`TZ=UTC; date`, which MultiExec's shell keeps for the lines after it).
///
/// Only names that change how output looks pass. Far more make a program load code (`LD_PRELOAD`,
/// `GCONV_PATH`), run another program (`PATH`, `PAGER`, `LESSOPEN`, `EDITOR`, `KUBECONFIG` with an exec
/// plugin, `DOCKER_HOST=ssh://…`), run shell code (`BASH_ENV`, `ENV`, `PS4`, `PROMPT_COMMAND`) or add
/// options that write (`LESS=-o file`, `SYSTEMD_LESS`), and that list has no end.
pub(super) fn harmless_assignment(word: &str) -> bool {
    let Some((name, value)) = word.split_once('=').filter(|_| is_assignment(word)) else {
        return false;
    };
    match name {
        // A locale with `/` is a folder of locale files to load.
        "LANG" | "LANGUAGE" => !value.contains(['/', '$']),
        name if name.starts_with("LC_") => !value.contains(['/', '$']),
        "TZ" | "TIME_STYLE" | "S_TIME_FORMAT" => true,
        "TERM" | "COLUMNS" | "LINES" | "NO_COLOR" | "SYSTEMD_COLORS" => true,
        // Empty or `cat` turns the pager off; systemd reads both.
        "PAGER" | "SYSTEMD_PAGER" => matches!(value, "" | "cat"),
        _ => false,
    }
}

/// The command `env` runs (`args` follow `env`) when before it env only clears the environment (`-i`,
/// `-`), unsets variables (`-u NAME`) and sets harmless ones: `env -i LC_ALL=C sort x` runs `sort x`.
/// None when env runs nothing, sets another variable or takes another option (`-S` splits a string
/// into a command, `-C` changes folder, …); [`writes`] then judges `env` itself.
pub(super) fn env_command(args: &[String]) -> Option<&[String]> {
    // Options come first; the first setting or `--` ends them.
    let mut options = true;
    let mut at = 0;
    while let Some(word) = args.get(at) {
        at += 1;
        if word.contains('$') {
            return None;
        }
        if is_assignment(word) {
            if !harmless_assignment(word) {
                return None;
            }
            options = false;
        } else if options && word == "--" {
            options = false;
        } else if let Some(long) = word.strip_prefix("--").filter(|_| options) {
            match long.split_once('=') {
                None if prefix_of(long, &["ignore-environment"]) => {}
                None if prefix_of(long, &["unset"]) => at += 1,
                Some((name, _)) if prefix_of(name, &["unset"]) => {}
                _ => return None,
            }
        } else if let Some(cluster) = word.strip_prefix('-').filter(|_| options) {
            // `-` alone is `-i`; a cluster such as `-iu NAME` or `-iuNAME`.
            for (i, letter) in cluster.char_indices() {
                match letter {
                    'i' => {}
                    'u' => {
                        if i + 1 == cluster.len() {
                            at += 1;
                        }
                        break;
                    }
                    _ => return None,
                }
            }
        } else {
            return Some(&args[at - 1..]);
        }
    }
    None
}

/// Verbs of `systemctl` that only read; without a verb it lists units.
const SYSTEMCTL_READS: &[&str] = &[
    "status",
    "show",
    "cat",
    "help",
    "list-units",
    "list-sockets",
    "list-timers",
    "list-automounts",
    "list-paths",
    "list-unit-files",
    "list-dependencies",
    "list-jobs",
    "list-machines",
    "is-active",
    "is-failed",
    "is-enabled",
    "is-system-running",
    "get-default",
    "show-environment",
    "whoami",
];

/// Long options of `systemctl` that take a value, so `--type service` is one option.
const SYSTEMCTL_VALUES: &[&str] = &[
    "type",
    "signal",
    "property",
    "host",
    "machine",
    "lines",
    "output",
    "state",
    "kill-whom",
    "kill-value",
    "root",
    "image",
    "image-policy",
    "job-mode",
    "what",
    "boot-loader-entry",
    "boot-loader-menu",
    "reboot-argument",
    "timestamp",
    "check-inhibitors",
    "message",
    "when",
    "legend",
    "preset-mode",
    "drop-in",
    "capsule",
];

/// Verbs of `timedatectl` that only read; without a verb it shows the status.
const TIMEDATECTL_READS: &[&str] = &[
    "status",
    "show",
    "list-timezones",
    "timesync-status",
    "show-timesync",
    "help",
];

/// Options of `journalctl` that delete, rotate or write journal files, or write keys or a cursor.
const JOURNALCTL_WRITES: &[&str] = &[
    "vacuum-size",
    "vacuum-time",
    "vacuum-files",
    "rotate",
    "flush",
    "sync",
    "relinquish-var",
    "smart-relinquish-var",
    "setup-keys",
    "update-catalog",
    "cursor-file",
];

/// `ip [OPTIONS] OBJECT [COMMAND ...]` reads when COMMAND is missing (it lists) or is show, list or
/// get. ip takes any abbreviation and tries its writing commands first, so `ip link s` is `set`.
fn ip_writes(args: &[String]) -> bool {
    let mut words = args.iter().map(String::as_str);
    let object = loop {
        // `ip` alone prints its help.
        let Some(word) = words.next() else {
            return false;
        };
        if word.contains('$') {
            return true;
        }
        let Some(option) = word.strip_prefix('-') else {
            break word;
        };
        let option = option.strip_prefix('-').unwrap_or(option);
        // -batch FILE runs the commands in a file.
        if prefix_of(option, &["batch"]) {
            return true;
        }
        if matches!(option, "n" | "netns" | "f" | "family" | "l" | "loops" | "rc" | "rcvbuf")
            && words.next().is_none_or(|value| value.contains('$'))
        {
            return true;
        }
    };
    let Some(command) = words.next() else {
        return false;
    };
    // `s` is `show` for addresses, routes and neighbours but `set` or `save` elsewhere.
    let show = if command == "s" {
        prefix_of(object, &["address", "route", "neighbor", "neighbour"])
    } else {
        prefix_of(command, &["show", "list", "lst", "get"])
    };
    !show
}

/// firewall-cmd reads when every option shows something (--state, --list-…, --get-…, --query-…,
/// --info-…) or picks what to show it for (--zone, --permanent, …).
fn firewall_cmd_writes(args: &[String]) -> bool {
    const SHOWS: &[&str] = &["--list-", "--get-", "--query-", "--info-"];
    const PICKS: &[&str] = &[
        "--state",
        "--zone",
        "--policy",
        "--permanent",
        "--ipset",
        "--service",
        "--helper",
        "--icmptype",
        "--direct",
        "--quiet",
        "-q",
    ];
    args.iter().any(|a| {
        let name = a.split_once('=').map_or(a.as_str(), |(name, _)| name);
        a.contains('$') || (a.starts_with('-') && !SHOWS.iter().any(|s| name.starts_with(s)) && !PICKS.contains(&name))
    })
}

/// How a command reads its options, as getopt_long does.
struct Spec {
    /// Short options that take a value, attached (`-n5`) or as the next word (`-n 5`).
    values: &'static str,
    /// Short options whose value can only be attached (`-Iseconds`).
    optional: &'static str,
    /// Long options that take a value: `--name value` uses the next word.
    long_values: &'static [&'static str],
}

/// A command line split into options and operands.
#[derive(Default)]
struct Parsed<'a> {
    /// Short option letters, in order, from clusters such as `-tulpn`.
    short: Vec<char>,
    /// Long option names, without the dashes and any `=value`.
    long: Vec<&'a str>,
    /// The other words, option values excluded. A word holding `$` is always here.
    operands: Vec<&'a str>,
}

impl Spec {
    fn parse<'a>(&self, args: &'a [String]) -> Parsed<'a> {
        let mut out = Parsed::default();
        let mut words = args.iter().map(String::as_str).peekable();
        while let Some(word) = words.next() {
            if word == "--" {
                out.operands.extend(words);
                break;
            }
            if word.contains('$') {
                out.operands.push(word);
            } else if let Some(long) = word.strip_prefix("--") {
                let name = long.split_once('=').map_or(long, |(name, _)| name);
                if name.len() == long.len() && prefix_of(name, self.long_values) {
                    skip_value(&mut words);
                }
                out.long.push(name);
            } else if let Some(cluster) = word.strip_prefix('-').filter(|c| !c.is_empty()) {
                for (at, letter) in cluster.char_indices() {
                    out.short.push(letter);
                    if self.values.contains(letter) {
                        if at + letter.len_utf8() == cluster.len() {
                            skip_value(&mut words);
                        }
                        break;
                    }
                    if self.optional.contains(letter) {
                        break;
                    }
                }
            } else {
                out.operands.push(word);
            }
        }
        out
    }
}

/// Skips the next word as an option's value, unless it holds `$` and may expand to something else.
fn skip_value<'a>(words: &mut Peekable<impl Iterator<Item = &'a str>>) {
    if words.peek().is_some_and(|w| !w.contains('$')) {
        words.next();
    }
}

impl Parsed<'_> {
    fn has_short(&self, letters: &str) -> bool {
        self.short.iter().any(|c| letters.contains(*c))
    }

    fn has_long(&self, options: &[&str]) -> bool {
        self.long.iter().any(|name| prefix_of(name, options))
    }
}

/// The bare name of an option word for tools that accept `-opt`, `--opt` and `-opt=value` the same way
/// (openssl's apps/lib/opt.c, lshw): leading dashes and a trailing `=value` are dropped, so
/// `--keylogfile=/tmp/k`, `-keylogfile` and `--out=x` become `keylogfile`, `keylogfile`, `out`.
fn bare_opt(word: &str) -> &str {
    word.trim_start_matches('-').split('=').next().unwrap_or("")
}

/// True when `name` is one of `options` or an abbreviation of one. getopt_long takes any unambiguous
/// abbreviation and refuses an ambiguous one, so counting both is safe.
fn prefix_of(name: &str, options: &[&str]) -> bool {
    !name.is_empty() && options.iter().any(|o| o.starts_with(name))
}
