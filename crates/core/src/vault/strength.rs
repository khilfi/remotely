//! SS-04, FD-07: how hard a new vault password or export passphrase is to guess, before the core takes
//! it. A small estimator in the spirit of zxcvbn (Wheeler, "zxcvbn: Low-Budget Password Strength
//! Estimation", USENIX Security 2016), without its large dictionaries and dependencies:
//!
//! * The password is covered by the cheapest run of pieces an attacker tries first: the most common
//!   passwords and words ([`COMMON`], also reversed, capitalised or with digits for letters), repeats
//!   (`aaaa`, `abcabc`), letters or digits in order (`abcd`, `9876`), rows and columns of keys
//!   (`qwerty`, `1qaz`), years and dates, and anything else at 10 guesses a character.
//! * Each piece costs a number of guesses and a run costs their product; the cheapest run is the
//!   estimate. Unlike zxcvbn there is no extra factor for the number of pieces, so it errs low.
//!   Separators (space, `-`, `_`, `.`...) are also tried left out, so `pass word 123` costs about what
//!   `password123` does.
//! * The score is zxcvbn's: 0 below 10^3 guesses, 1 below 10^6, 2 below 10^8, 3 below 10^10, 4 above.
//!
//! A new password or passphrase needs [`MIN_SCORE`] (3) or more. A few random words pass with room to
//! spare; `Password123!`, `aaaaaaaaaaaa` or `qwertyuiop12` don't. The hint never quotes the password.

use std::collections::HashMap;
use std::sync::LazyLock;

use serde::Serialize;

use super::{MAX_PASSWORD_LEN, MIN_PASSWORD_LEN};

/// The lowest score a new vault password or export passphrase needs: zxcvbn's 3, at least 10^8
/// guesses.
pub const MIN_SCORE: u8 = 3;

/// Only the first this many characters are scored, which bounds the work per keystroke. The rest could
/// only add guesses, so a longer password is never scored higher than it is.
const SCAN_LEN: usize = 256;

/// log10 of the guesses one character nobody can predict costs (zxcvbn's brute-force cardinality 10).
const PER_CHAR: f64 = 1.0;

/// log10 of 50: the fewest guesses a piece costs when it isn't the whole password (zxcvbn's
/// MIN_SUBMATCH_GUESSES_MULTI_CHAR), so that splitting into small pieces doesn't look cheaper than it is.
const MIN_PIECE: f64 = 1.698_97;

/// Repeats of a chunk longer than this aren't looked for.
const MAX_REPEAT_UNIT: usize = 32;

/// How far down repeats of repeats are looked into.
const MAX_DEPTH: u8 = 2;

/// Key positions and the average number of neighbours on a QWERTY keyboard (zxcvbn's figures).
const KEYBOARD_STARTS: f64 = 94.0;
const KEYBOARD_DEGREE: f64 = 4.6;

/// Characters people put between words.
const SEPARATORS: &[char] = &[' ', '-', '_', '.', ',', '+', '/', '\\', '|', ':', ';'];

/// Separators in dates (`01/02/1990`, `1990-02-01`).
const DATE_SEPARATORS: &[char] = &[' ', '/', '\\', '_', '.', '-'];

/// How strong a candidate password is, for the UI's meter. The core's own check
/// ([`super::check_new_password`]) decides; this says why.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Strength {
    /// 0 (guessed at once) to 4 (very hard to guess). At most 2 while the length is wrong.
    pub score: u8,
    /// The vault would take it as a new password or passphrase.
    pub acceptable: bool,
    /// One or two short sentences: what makes it weak, or how strong it is. Empty for an empty
    /// password. Never quotes the password.
    pub hint: String,
}

/// What a piece of the password is, for the hint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Common,
    Repeat,
    Sequence,
    Keyboard,
    Date,
}

/// Repeated chunks already costed during one estimate: a periodic password has few distinct ones.
type Chunks = HashMap<Vec<char>, f64>;

#[derive(Debug)]
struct Piece {
    start: usize,
    end: usize,
    /// log10 of the guesses it costs.
    cost: f64,
    kind: Kind,
}

/// SS-04, FD-07: scores a candidate vault password or export passphrase. Cheap enough to run on every
/// keystroke; never logs or stores the text.
pub fn password_strength(password: &str) -> Strength {
    if password.is_empty() {
        return Strength {
            score: 0,
            acceptable: false,
            hint: String::new(),
        };
    }
    let length = password.chars().count();
    if length > MAX_PASSWORD_LEN {
        return Strength {
            score: 0,
            acceptable: false,
            hint: format!("Too long: at most {MAX_PASSWORD_LEN} characters."),
        };
    }
    let chars: Vec<char> = password.chars().take(SCAN_LEN).collect();
    let (guesses, weakest) = estimate(&chars);
    let score = score_of(guesses);
    if length < MIN_PASSWORD_LEN || password.trim().is_empty() {
        return Strength {
            score: score.min(MIN_SCORE - 1),
            acceptable: false,
            hint: format!("Use at least {MIN_PASSWORD_LEN} characters. A few unrelated words make a good one."),
        };
    }
    let hint = match score {
        4 => "Strong.".to_owned(),
        s if s >= MIN_SCORE => "Good. Another word makes it stronger.".to_owned(),
        _ => format!(
            "{} Add a few unrelated words, or generate a passphrase.",
            reason(weakest)
        ),
    };
    Strength {
        score,
        acceptable: score >= MIN_SCORE,
        hint,
    }
}

fn reason(kind: Option<Kind>) -> &'static str {
    match kind {
        Some(Kind::Common) => "It is built on a common password or word.",
        Some(Kind::Repeat) => "Repeated characters or chunks are easy to guess.",
        Some(Kind::Sequence) => "Letters or digits in order are easy to guess.",
        Some(Kind::Keyboard) => "Rows of keys on the keyboard are easy to guess.",
        Some(Kind::Date) => "Years and dates are easy to guess.",
        None => "It is too easy to guess.",
    }
}

/// zxcvbn's score for log10 of the guesses.
fn score_of(guesses: f64) -> u8 {
    match guesses {
        g if g < 3.0 => 0,
        g if g < 6.0 => 1,
        g if g < 8.0 => 2,
        g if g < 10.0 => 3,
        _ => 4,
    }
}

/// log10 of the guesses `chars` costs, and the kind of its longest piece. The cheaper of the password
/// as it is and without its separators (plus a guess at which separator and where each went).
fn estimate(chars: &[char]) -> (f64, Option<Kind>) {
    let mut chunks = Chunks::new();
    let plain = cover(chars, 0, &mut chunks);
    let kept: Vec<char> = chars.iter().copied().filter(|c| !SEPARATORS.contains(c)).collect();
    let removed = chars.len() - kept.len();
    if removed == 0 || kept.is_empty() {
        return plain;
    }
    let (joined, kind) = cover(&kept, 0, &mut chunks);
    let joined = joined + (SEPARATORS.len() as f64).log10() + removed as f64 * ((kept.len() + 1) as f64).log10();
    if joined < plain.0 {
        (joined, kind)
    } else {
        plain
    }
}

/// The cheapest run of pieces that covers `chars` (zxcvbn's search): log10 of its guesses and the kind
/// of its longest piece.
fn cover(chars: &[char], depth: u8, chunks: &mut Chunks) -> (f64, Option<Kind>) {
    let n = chars.len();
    if n == 0 {
        return (0.0, None);
    }
    let lower: Vec<char> = chars.iter().map(|&c| c.to_lowercase().next().unwrap_or(c)).collect();
    let mut pieces = Vec::new();
    common_words(chars, &lower, &mut pieces);
    repeats(chars, depth, chunks, &mut pieces);
    sequences(chars, &mut pieces);
    keyboard(&lower, &mut pieces);
    dates(chars, &mut pieces);

    let mut ending_at: Vec<Vec<usize>> = vec![Vec::new(); n + 1];
    for (index, piece) in pieces.iter_mut().enumerate() {
        if piece.end - piece.start < n {
            piece.cost = piece.cost.max(MIN_PIECE);
        }
        piece.cost = piece.cost.max(0.0);
        ending_at[piece.end].push(index);
    }
    let mut best = vec![0.0f64; n + 1];
    let mut via: Vec<Option<usize>> = vec![None; n + 1];
    for end in 1..=n {
        best[end] = best[end - 1] + PER_CHAR;
        for &index in &ending_at[end] {
            let piece = &pieces[index];
            let cost = best[piece.start] + piece.cost;
            if cost < best[end] {
                best[end] = cost;
                via[end] = Some(index);
            }
        }
    }
    let (mut kind, mut longest, mut at) = (None, 0, n);
    while at > 0 {
        match via[at] {
            Some(index) => {
                let piece = &pieces[index];
                if piece.end - piece.start > longest {
                    longest = piece.end - piece.start;
                    kind = Some(piece.kind);
                }
                at = piece.start;
            }
            None => at -= 1,
        }
    }
    (best[n], kind)
}

// ---- Common passwords and words -------------------------------------------------------------------

/// Common passwords and words, most common first: the rank is the guesses. Lower case, four characters
/// or more; digits in place of letters, capitals and reversed spellings are found from these. Kept
/// short on purpose: anything else counts as unpredictable text.
pub(super) const COMMON: &[&str] = &[
    "password",
    "123456789",
    "qwerty",
    "iloveyou",
    "admin",
    "remotely",
    "welcome",
    "letmein",
    "monkey",
    "dragon",
    "abc123",
    "football",
    "baseball",
    "sunshine",
    "master",
    "shadow",
    "princess",
    "qwertyuiop",
    "superman",
    "batman",
    "trustno1",
    "correcthorsebatterystaple",
    "troubador",
    "1q2w3e4r",
    "1qaz2wsx",
    "zaq12wsx",
    "qazwsx",
    "qwe123",
    "123qwe",
    "q1w2e3r4",
    "a1b2c3",
    "112233",
    "11223344",
    "159753",
    "147258369",
    "789456123",
    "changeme",
    "default",
    "secret",
    "login",
    "access",
    "administrator",
    "root",
    "toor",
    "guest",
    "test",
    "testing",
    "temp",
    "temporary",
    "pass",
    "passwd",
    "passphrase",
    "passwort",
    "motdepasse",
    "contrasena",
    "senha",
    "parola",
    "wachtwoord",
    "user",
    "username",
    "system",
    "server",
    "network",
    "windows",
    "linux",
    "ubuntu",
    "debian",
    "centos",
    "redhat",
    "vmware",
    "virtualbox",
    "vault",
    "secure",
    "security",
    "private",
    "support",
    "service",
    "office",
    "manager",
    "company",
    "business",
    "customer",
    "client",
    "backup",
    "database",
    "oracle",
    "mysql",
    "postgres",
    "cisco",
    "router",
    "firewall",
    "putty",
    "mobaxterm",
    "openssh",
    "docker",
    "kubernetes",
    "computer",
    "internet",
    "opensesame",
    "michael",
    "jennifer",
    "hunter",
    "freedom",
    "whatever",
    "starwars",
    "charlie",
    "jordan",
    "liverpool",
    "chelsea",
    "arsenal",
    "hello",
    "hockey",
    "soccer",
    "killer",
    "pepper",
    "ginger",
    "cheese",
    "summer",
    "winter",
    "spring",
    "autumn",
    "flower",
    "lovely",
    "loveme",
    "angel",
    "maggie",
    "buster",
    "ranger",
    "harley",
    "hannah",
    "thomas",
    "robert",
    "daniel",
    "andrew",
    "joshua",
    "matthew",
    "jessica",
    "ashley",
    "amanda",
    "nicole",
    "michelle",
    "tigger",
    "cookie",
    "banana",
    "orange",
    "purple",
    "silver",
    "golden",
    "diamond",
    "matrix",
    "mustang",
    "corvette",
    "ferrari",
    "porsche",
    "mercedes",
    "yankees",
    "dallas",
    "london",
    "paris",
    "berlin",
    "qwertz",
    "azerty",
    "asdfgh",
    "zxcvbn",
    "love",
    "money",
    "jesus",
    "blessed",
    "family",
    "friends",
    "forever",
    "baby",
    "babygirl",
    "lucky",
    "magic",
    "music",
    "pokemon",
    "minecraft",
    "fortnite",
    "naruto",
    "google",
    "facebook",
    "microsoft",
    "apple",
    "samsung",
    "mickey",
    "snoopy",
    "superstar",
    "rockstar",
    "player",
    "monday",
    "tuesday",
    "wednesday",
    "thursday",
    "friday",
    "saturday",
    "sunday",
    "january",
    "february",
    "march",
    "april",
    "june",
    "july",
    "august",
    "september",
    "october",
    "november",
    "december",
];

/// Every place a common word starts, as it is, reversed (twice the guesses), capitalised or with digits
/// and symbols for letters (`p@ssw0rd`).
fn common_words(chars: &[char], lower: &[char], out: &mut Vec<Piece>) {
    /// Each word forwards and backwards (none for a palindrome), with its rank.
    static SPELLINGS: LazyLock<Vec<(usize, Vec<char>, f64)>> = LazyLock::new(|| {
        let mut spellings = Vec::new();
        for (rank, word) in COMMON.iter().enumerate() {
            let forward: Vec<char> = word.chars().collect();
            let backward: Vec<char> = forward.iter().rev().copied().collect();
            if backward != forward {
                spellings.push((rank, backward, 2.0));
            }
            spellings.push((rank, forward, 1.0));
        }
        spellings
    });
    let n = lower.len();
    for (rank, spelling, factor) in SPELLINGS.iter() {
        let len = spelling.len();
        if len > n {
            continue;
        }
        for start in 0..=n - len {
            let end = start + len;
            if let Some(subs) = l33t_match(&lower[start..end], spelling) {
                let guesses = (rank + 1) as f64 * case_variations(&chars[start..end]) * 2f64.powi(subs as i32) * factor;
                out.push(Piece {
                    start,
                    end,
                    cost: guesses.log10(),
                    kind: Kind::Common,
                });
            }
        }
    }
}

/// `Some(number of substituted characters)` when `token` (lower case) spells `word`, digits and
/// symbols standing in for letters allowed.
fn l33t_match(token: &[char], word: &[char]) -> Option<u32> {
    let mut subs = 0;
    for (&c, &letter) in token.iter().zip(word) {
        if c == letter {
            continue;
        }
        if l33t(c).contains(letter) {
            subs += 1;
        } else {
            return None;
        }
    }
    Some(subs)
}

/// The letters a digit or symbol stands in for.
fn l33t(c: char) -> &'static str {
    match c {
        '4' | '@' => "a",
        '8' => "b",
        '(' | '{' | '[' | '<' => "c",
        '3' => "e",
        '6' | '9' => "g",
        '1' | '|' => "il",
        '!' => "i",
        '0' => "o",
        '$' | '5' => "s",
        '7' | '+' => "t",
        '%' => "x",
        '2' => "z",
        _ => "",
    }
}

/// How many ways of capitalising the token an attacker tries before this one (zxcvbn): none for lower
/// case, two for a capital at the start or end or all capitals, more for capitals inside.
fn case_variations(token: &[char]) -> f64 {
    let upper = token.iter().filter(|c| c.is_uppercase()).count();
    let lower = token.iter().filter(|c| c.is_lowercase()).count();
    if upper == 0 {
        return 1.0;
    }
    if lower == 0 {
        return 2.0;
    }
    let first = token.first().is_some_and(|c| c.is_uppercase());
    let last = token.last().is_some_and(|c| c.is_uppercase());
    if upper == 1 && (first || last) {
        return 2.0;
    }
    (1..=upper.min(lower)).map(|k| binomial(upper + lower, k)).sum()
}

fn binomial(n: usize, k: usize) -> f64 {
    (0..k).fold(1.0, |acc, i| acc * (n - i) as f64 / (i + 1) as f64)
}

// ---- Repeats, sequences, keyboard -----------------------------------------------------------------

/// From each position, the chunk repeated the most (`aaaa`, `abcabc`, `hunter2hunter2`): the chunk's
/// own cost times the number of times it is said, and times its length again when it stops part way
/// through one more (`abcabcab`).
fn repeats(chars: &[char], depth: u8, chunks: &mut Chunks, out: &mut Vec<Piece>) {
    let n = chars.len();
    for start in 0..n {
        let mut best: Option<(usize, usize)> = None;
        for unit in 1..=((n - start) / 2).min(MAX_REPEAT_UNIT) {
            let chunk = &chars[start..start + unit];
            let mut count = 1;
            while start + (count + 1) * unit <= n && chars[start + count * unit..start + (count + 1) * unit] == *chunk {
                count += 1;
            }
            if count >= 2 && best.is_none_or(|(u, c)| unit * count > u * c) {
                best = Some((unit, count));
            }
        }
        if let Some((unit, count)) = best {
            let chunk = &chars[start..start + unit];
            let base = match chunks.get(chunk) {
                Some(&cost) => cost,
                None => {
                    let cost = if depth < MAX_DEPTH {
                        cover(chunk, depth + 1, chunks).0
                    } else {
                        unit as f64 * PER_CHAR
                    };
                    chunks.insert(chunk.to_vec(), cost);
                    cost
                }
            };
            let end = start + unit * count;
            let cost = base + (count as f64).log10();
            out.push(Piece {
                start,
                end,
                cost,
                kind: Kind::Repeat,
            });
            let tail = chars[end..].iter().zip(chunk).take_while(|(a, b)| a == b).count();
            if tail > 0 {
                out.push(Piece {
                    start,
                    end: end + tail,
                    cost: cost + (unit as f64).log10(),
                    kind: Kind::Repeat,
                });
            }
        }
    }
}

/// `a`-`z`, `A`-`Z` or `0`-`9`: a sequence stays in one.
fn class_of(c: char) -> Option<u8> {
    if c.is_ascii_lowercase() {
        Some(0)
    } else if c.is_ascii_uppercase() {
        Some(1)
    } else if c.is_ascii_digit() {
        Some(2)
    } else {
        None
    }
}

/// Three or more letters or digits a fixed step apart (`abcd`, `9876`, `2468`), from each position.
fn sequences(chars: &[char], out: &mut Vec<Piece>) {
    let n = chars.len();
    for start in 0..n.saturating_sub(2) {
        let class = class_of(chars[start]);
        if class.is_none() || class_of(chars[start + 1]) != class {
            continue;
        }
        let step = chars[start + 1] as i64 - chars[start] as i64;
        if step == 0 || step.abs() > 5 {
            continue;
        }
        let mut end = start + 2;
        while end < n && class_of(chars[end]) == class && chars[end] as i64 - chars[end - 1] as i64 == step {
            end += 1;
        }
        if end - start < 3 {
            continue;
        }
        let first = chars[start];
        let mut base = if "aAzZ019".contains(first) {
            4.0
        } else if first.is_ascii_digit() {
            10.0
        } else {
            26.0
        };
        if step < 0 {
            base *= 2.0;
        }
        out.push(Piece {
            start,
            end,
            cost: (base * (end - start) as f64).log10(),
            kind: Kind::Sequence,
        });
    }
}

/// Rows and columns of keys (lower case): US QWERTY, QWERTZ and AZERTY rows, the shifted digit row and
/// the main block's columns. Read both ways.
const KEY_LINES: &[&str] = &[
    "`1234567890-=",
    "qwertyuiop[]\\",
    "asdfghjkl;'",
    "zxcvbnm,./",
    "~!@#$%^&*()_+",
    "qwertzuiop",
    "yxcvbnm",
    "azertyuiop",
    "qsdfghjklm",
    "wxcvbn",
    "1qaz",
    "2wsx",
    "3edc",
    "4rfv",
    "5tgb",
    "6yhn",
    "7ujm",
    "8ik,",
    "9ol.",
    "0p;/",
];

/// Four or more keys in a row or column, from each position.
fn keyboard(lower: &[char], out: &mut Vec<Piece>) {
    let n = lower.len();
    static LINES: LazyLock<Vec<Vec<char>>> = LazyLock::new(|| {
        KEY_LINES
            .iter()
            .flat_map(|line| [line.chars().collect(), line.chars().rev().collect()])
            .collect()
    });
    for start in 0..n {
        let mut longest = 0;
        for line in LINES.iter() {
            let Some(at) = line.iter().position(|&k| k == lower[start]) else {
                continue;
            };
            let len = line[at..]
                .iter()
                .zip(&lower[start..])
                .take_while(|(k, c)| k == c)
                .count();
            longest = longest.max(len);
        }
        if longest >= 4 {
            let guesses = (longest - 1) as f64 * KEYBOARD_STARTS * KEYBOARD_DEGREE;
            out.push(Piece {
                start,
                end: start + longest,
                cost: guesses.log10(),
                kind: Kind::Keyboard,
            });
        }
    }
}

// ---- Years and dates -------------------------------------------------------------------------------

/// Where to cut 4 to 8 digits into day, month and year (zxcvbn's DATE_SPLITS): `(k, l)` reads
/// `s[..k]`, `s[k..l]`, `s[l..]`.
fn date_splits(len: usize) -> &'static [(usize, usize)] {
    match len {
        4 => &[(1, 2), (2, 3)],
        5 => &[(1, 3), (2, 3)],
        6 => &[(1, 2), (2, 4), (4, 5)],
        7 => &[(1, 3), (2, 3), (4, 5), (4, 6)],
        8 => &[(2, 4), (4, 6)],
        _ => &[],
    }
}

/// The digits as a number; `None` if any isn't a digit (or there are too many).
fn number(chars: &[char]) -> Option<u32> {
    if chars.is_empty() || chars.len() > 9 {
        return None;
    }
    chars.iter().try_fold(0u32, |acc, c| Some(acc * 10 + c.to_digit(10)?))
}

/// The year, when the three numbers make a day, a month and a year in some order (the year first or
/// last; two digits mean 19xx above 50, else 20xx).
fn date_year(a: u32, b: u32, c: u32) -> Option<u32> {
    if b == 0 || b > 31 {
        return None;
    }
    let ints = [a, b, c];
    let over_12 = ints.iter().filter(|&&i| i > 12).count();
    let over_31 = ints.iter().filter(|&&i| i > 31).count();
    let zero = ints.iter().filter(|&&i| i == 0).count();
    if over_31 >= 2 || over_12 == 3 || zero >= 2 {
        return None;
    }
    let day_month = |x: u32, y: u32| {
        ((1..=31).contains(&x) && (1..=12).contains(&y)) || ((1..=31).contains(&y) && (1..=12).contains(&x))
    };
    let orders = [(c, a, b), (a, b, c)];
    if let Some(&(year, _, _)) = orders
        .iter()
        .find(|&&(year, x, y)| (1000..=2099).contains(&year) && day_month(x, y))
    {
        return Some(year);
    }
    orders
        .iter()
        .find(|&&(year, x, y)| year < 100 && day_month(x, y))
        .map(|&(year, _, _)| if year > 50 { 1900 + year } else { 2000 + year })
}

/// Guesses for a year: how far it is from this one, at least 20 (zxcvbn's MIN_YEAR_SPACE).
fn year_guesses(year: u32) -> f64 {
    let now = i64::from(time::OffsetDateTime::now_utc().year());
    (i64::from(year) - now).unsigned_abs().max(20) as f64
}

/// Years (1900 to 2099) and dates, with or without separators, from each position.
fn dates(chars: &[char], out: &mut Vec<Piece>) {
    let n = chars.len();
    let mut push = |start: usize, end: usize, guesses: f64| {
        out.push(Piece {
            start,
            end,
            cost: guesses.log10(),
            kind: Kind::Date,
        })
    };
    for start in 0..n {
        if let Some(year) = chars.get(start..start + 4).and_then(number) {
            if (1900..=2099).contains(&year) {
                push(start, start + 4, year_guesses(year));
            }
        }
        for len in 4..=8 {
            let Some(digits) = chars.get(start..start + len) else {
                break;
            };
            if number(digits).is_none() {
                break;
            }
            let fewest = date_splits(len)
                .iter()
                .filter_map(|&(k, l)| date_year(number(&digits[..k])?, number(&digits[k..l])?, number(&digits[l..])?))
                .map(year_guesses)
                .fold(f64::INFINITY, f64::min);
            if fewest.is_finite() {
                push(start, start + len, 365.0 * fewest);
            }
        }
        if let Some((end, year)) = separated_date(chars, start) {
            push(start, end, 365.0 * year_guesses(year) * 4.0);
        }
    }
}

/// End of the run of digits from `start`.
fn digits_end(chars: &[char], start: usize) -> usize {
    start
        + chars[start.min(chars.len())..]
            .iter()
            .take_while(|c| c.is_ascii_digit())
            .count()
}

/// A date with separators starting at `start` (`1-4 digits, separator, 1-2 digits, the same
/// separator, 1-4 digits`): its end and year.
fn separated_date(chars: &[char], start: usize) -> Option<(usize, u32)> {
    if start > 0 && chars.get(start - 1).is_some_and(char::is_ascii_digit) {
        return None;
    }
    let a_end = digits_end(chars, start);
    let separator = *chars.get(a_end)?;
    if !(1..=4).contains(&(a_end - start)) || !DATE_SEPARATORS.contains(&separator) {
        return None;
    }
    let b_end = digits_end(chars, a_end + 1);
    if !(1..=2).contains(&(b_end - a_end - 1)) || chars.get(b_end) != Some(&separator) {
        return None;
    }
    let c_end = digits_end(chars, b_end + 1);
    if !(1..=4).contains(&(c_end - b_end - 1)) {
        return None;
    }
    let year = date_year(
        number(&chars[start..a_end])?,
        number(&chars[a_end + 1..b_end])?,
        number(&chars[b_end + 1..c_end])?,
    )?;
    Some((c_end, year))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn score(password: &str) -> u8 {
        password_strength(password).score
    }

    #[test]
    fn common_patterns_are_refused() {
        for weak in [
            "Password123!",
            "aaaaaaaaaaaa",
            "qwertyuiop12",
            "P@ssw0rd2024",
            "Summer2026!",
            "Remotely2026!",
            "welcome@remotely",
            "hunter2hunter2",
            "iloveyou12345",
            "abcdefghijkl",
            "0123456789",
            "9876543210",
            "zxcvbnm,./",
            "1q2w3e4r5t",
            "Tr0ub4dor&3",
            "correct horse battery staple",
            "pass word 1234",
            "password password password",
            "admin-admin-admin",
            "1990-02-01",
            "abcabcabcab",
            "qazwsxedc!",
            "!@#$%^&*()",
        ] {
            let strength = password_strength(weak);
            assert!(!strength.acceptable, "{weak}: {strength:?}");
            assert!(strength.score < MIN_SCORE, "{weak}: {strength:?}");
        }
    }

    #[test]
    fn a_few_random_words_pass_easily() {
        for strong in [
            "tulip anvil orbit canyon",
            "maple-orbit-tulip-canyon-velvet-ember",
            "five unrelated words here",
            "Blue-Sky-Over-Harbor",
            "export passphrase example",
            "x.K-9_mQ2z",
            "k7#Qp2!vZm",
        ] {
            let strength = password_strength(strong);
            assert!(strength.acceptable, "{strong}: {strength:?}");
            assert_eq!(strength.score, 4, "{strong}: {strength:?}");
            assert_eq!(strength.hint, "Strong.");
        }
    }

    #[test]
    fn each_pattern_lowers_the_score() {
        assert!(score("qwertyuiop") < 2);
        assert!(score("aaaaaaaaaa") == 0);
        assert!(score("abcdefghij") == 0);
        assert!(score("password") == 0);
        assert!(score("drowssap") <= 1);
        assert!(score("PASSWORD") <= 1);
        assert!(score("p4$$w0rd") <= 1);
        assert!(score("19900201") <= 2);
        assert!(score("01.02.1990") <= 2);
        // The same length of unpredictable text is far stronger.
        assert_eq!(score("vkqmzrwxty"), 4);
    }

    #[test]
    fn length_bounds_come_first() {
        let short = password_strength("k7#Qp2!v");
        assert!(!short.acceptable);
        assert!(short.score < MIN_SCORE);
        assert!(short.hint.contains("at least 10 characters"), "{short:?}");

        let spaces = password_strength("            ");
        assert!(!spaces.acceptable);
        assert!(spaces.hint.contains("at least 10 characters"), "{spaces:?}");

        let long = password_strength(&"word ".repeat(MAX_PASSWORD_LEN));
        assert!(!long.acceptable);
        assert!(long.hint.contains("at most"), "{long:?}");

        let empty = password_strength("");
        assert_eq!((empty.score, empty.acceptable, empty.hint.as_str()), (0, false, ""));
    }

    #[test]
    fn hints_say_why_without_quoting_the_password() {
        for (weak, says) in [
            ("Password123!", "common password"),
            ("aaaaaaaaaaaa", "Repeated"),
            ("abcdefghijkl", "in order"),
            ("zxcvbnm,./", "keyboard"),
            ("19900201199002", "dates"),
        ] {
            let strength = password_strength(weak);
            assert!(strength.hint.contains(says), "{weak}: {strength:?}");
            assert!(!strength.hint.contains(weak), "{weak}: {strength:?}");
            assert!(strength.hint.contains("generate a passphrase"), "{weak}: {strength:?}");
        }
    }

    #[test]
    fn long_and_odd_input_is_scored_quickly_and_never_panics() {
        // A small deterministic generator over letters, digits, separators, symbols and non-ASCII text.
        let alphabet: Vec<char> = "aAzZ09qwerty12345 -_./\\|!@#$%^&*()éÉßØж😀\u{0301}".chars().collect();
        let mut state: u64 = 0x2545_f491_4f6c_dd1d;
        for round in 0..300 {
            let len = (round * 7) % 300;
            let text: String = (0..len)
                .map(|_| {
                    state ^= state << 13;
                    state ^= state >> 7;
                    state ^= state << 17;
                    alphabet[(state % alphabet.len() as u64) as usize]
                })
                .collect();
            let strength = password_strength(&text);
            assert!(strength.score <= 4);
        }
        // Worst cases for the repeat search, at the most the vault takes.
        for text in [
            "a".repeat(MAX_PASSWORD_LEN),
            "ab".repeat(MAX_PASSWORD_LEN / 2),
            "abcdefghijklmnopqrstuvwxyz012345".repeat(MAX_PASSWORD_LEN / 32),
            "password ".repeat(MAX_PASSWORD_LEN / 9),
        ] {
            assert!(!password_strength(&text).acceptable, "{}", &text[..20]);
        }
        assert!(password_strength(&"vkqmzrwxty ".repeat(MAX_PASSWORD_LEN / 11)).score <= 4);
    }

    #[test]
    fn the_word_list_is_clean() {
        let mut seen = std::collections::HashSet::new();
        for word in COMMON {
            assert!(word.len() >= 4, "{word}");
            assert!(
                word.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit()),
                "{word}"
            );
            assert!(seen.insert(*word), "{word} twice");
        }
    }

    #[test]
    fn dates_are_read_like_zxcvbn() {
        assert_eq!(date_year(1, 2, 1990), Some(1990));
        assert_eq!(date_year(1990, 2, 1), Some(1990));
        assert_eq!(date_year(12, 31, 99), Some(1999));
        assert_eq!(date_year(1, 2, 3), Some(2003));
        assert_eq!(date_year(13, 13, 13), None);
        assert_eq!(date_year(45, 2, 77), None);
        assert_eq!(
            separated_date(&"7/4/1976".chars().collect::<Vec<_>>(), 0),
            Some((8, 1976))
        );
        assert_eq!(separated_date(&"7/4-1976".chars().collect::<Vec<_>>(), 0), None);
    }
}
