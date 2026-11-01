//! FD-08: what the handover pack's `index.html` is made of. Every text goes through [`escape`] (after the table
//! model's [`super::table::clean`], which redacts secrets), so nothing in a name, a tag or a note becomes markup. The
//! page runs no script and asks for nothing outside itself: [`csp`] allows only the page's own style sheet (by its
//! hash) and `data:` images (the topology diagram), and [`page`] is the only place the `<head>` is written.

use base64::Engine;
use sha2::{Digest, Sha256};

use super::table::{Cell, Sheet};
use crate::untrusted::is_format_char;

/// `&`, `<`, `>`, `"` and `'` as entities; control and invisible format characters left out (a tab or line break
/// stays, as a space would read).
pub fn escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 16);
    for c in text.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            '\n' | '\t' => out.push(c),
            c if c.is_control() || is_format_char(c) => {}
            c => out.push(c),
        }
    }
    out
}

/// The page's style sheet. Print-friendly: page breaks before each part, tables that split across pages with their
/// heading repeated, no backgrounds a printer drops.
pub const STYLE: &str = "\
:root{color-scheme:light;font-family:'Segoe UI',system-ui,-apple-system,sans-serif;font-size:14px;color:#1f2328;}\
body{margin:0 auto;max-width:1200px;padding:24px 32px;line-height:1.45;}\
h1{font-size:28px;margin:0 0 8px;}h2{font-size:20px;margin:32px 0 8px;border-bottom:1px solid #d0d7de;padding-bottom:4px;}\
h3{font-size:16px;margin:20px 0 6px;}\
.cover{padding:48px 0 32px;border-bottom:2px solid #1f2328;margin-bottom:24px;}\
.cover dl{display:grid;grid-template-columns:max-content 1fr;gap:4px 16px;margin:16px 0 0;}\
.cover dt{color:#59636e;}.cover dd{margin:0;}\
.muted{color:#59636e;}.small{font-size:12px;}\
nav ol{margin:8px 0;padding-left:20px;}\
table{border-collapse:collapse;width:100%;margin:8px 0 16px;font-size:12px;}\
th,td{border:1px solid #d0d7de;padding:3px 6px;text-align:left;vertical-align:top;overflow-wrap:anywhere;}\
th{background:#f6f8fa;font-weight:600;}thead{display:table-header-group;}tr{break-inside:avoid;}\
.num{text-align:right;white-space:nowrap;}\
.ok{color:#1a7f37;}.bad{color:#cf222e;}\
pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#f6f8fa;border:1px solid #d0d7de;padding:6px 8px;font-size:11px;}\
.job{border:1px solid #d0d7de;border-radius:6px;padding:8px 12px;margin:10px 0;break-inside:avoid-page;}\
.job h3{margin:0 0 4px;}\
.note{border-left:3px solid #d0d7de;padding:0 12px;margin:12px 0;}\
.note-link{text-decoration:underline dotted;}.note-url{color:#59636e;font-size:12px;}\
.note-image,.note-link-refused{color:#59636e;}\
.topology img{max-width:100%;height:auto;border:1px solid #d0d7de;}\
@media print{body{padding:0;max-width:none;}section{break-before:page;}.cover{break-after:page;}\
a{color:inherit;text-decoration:none;}}";

/// The Content Security Policy: nothing but the page's own style sheet and `data:` images. No script, no request
/// to anywhere, no form, no base URL.
pub fn csp() -> String {
    let hash = base64::engine::general_purpose::STANDARD.encode(Sha256::digest(STYLE.as_bytes()));
    format!("default-src 'none'; img-src data:; style-src 'sha256-{hash}'; base-uri 'none'; form-action 'none'")
}

/// The whole page around `body`, which must already be escaped.
pub fn page(title: &str, body: &str) -> String {
    format!(
        "<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n\
<meta http-equiv=\"Content-Security-Policy\" content=\"{csp}\">\n\
<meta name=\"referrer\" content=\"no-referrer\">\n\
<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n\
<title>{title}</title>\n<style>{STYLE}</style>\n</head>\n<body>\n{body}</body>\n</html>\n",
        csp = escape(&csp()),
        title = escape(title),
    )
}

/// A sheet as a table, with only the columns named (by heading, in that order); every column when `columns` is
/// empty. `None` when the sheet has no rows.
pub fn table(sheet: &Sheet, columns: &[&str]) -> Option<String> {
    if sheet.rows.is_empty() {
        return None;
    }
    let picked: Vec<usize> = if columns.is_empty() {
        (0..sheet.columns.len()).collect()
    } else {
        columns
            .iter()
            .filter_map(|title| sheet.columns.iter().position(|c| c.title == *title))
            .collect()
    };
    let mut out = String::from("<table>\n<thead><tr>");
    for &i in &picked {
        out.push_str(&format!("<th>{}</th>", escape(sheet.columns[i].title)));
    }
    out.push_str("</tr></thead>\n<tbody>\n");
    for row in &sheet.rows {
        out.push_str("<tr>");
        for &i in &picked {
            let cell = row.get(i).unwrap_or(&Cell::Empty);
            let class = match cell {
                Cell::Int(_) | Cell::Number(_) => " class=\"num\"",
                _ => "",
            };
            out.push_str(&format!("<td{class}>{}</td>", escape(&cell.display())));
        }
        out.push_str("</tr>\n");
    }
    out.push_str("</tbody>\n</table>\n");
    Some(out)
}

/// A table from headings and rows of text already cleaned.
pub fn simple_table(headings: &[&str], rows: &[Vec<String>]) -> String {
    let mut out = String::from("<table>\n<thead><tr>");
    for h in headings {
        out.push_str(&format!("<th>{}</th>", escape(h)));
    }
    out.push_str("</tr></thead>\n<tbody>\n");
    for row in rows {
        out.push_str("<tr>");
        for cell in row {
            out.push_str(&format!("<td>{}</td>", escape(cell)));
        }
        out.push_str("</tr>\n");
    }
    out.push_str("</tbody>\n</table>\n");
    out
}

#[cfg(test)]
mod tests {
    use super::super::table::col;
    use super::*;

    #[test]
    fn markup_in_text_is_only_text() {
        assert_eq!(
            escape("<script>alert('x')</script> & \"q\""),
            "&lt;script&gt;alert(&#39;x&#39;)&lt;/script&gt; &amp; &quot;q&quot;"
        );
        assert_eq!(escape("a\u{202E}b\u{0}c"), "abc");
        assert_eq!(escape("line\nbreak"), "line\nbreak");
    }

    #[test]
    fn the_page_has_a_strict_policy_and_no_script() {
        let html = page("Handover <x>", "<p>hi</p>\n");
        assert!(html.contains("http-equiv=\"Content-Security-Policy\""));
        assert!(html.contains("default-src &#39;none&#39;"), "{html}");
        assert!(html.contains("<title>Handover &lt;x&gt;</title>"));
        assert!(!html.to_lowercase().contains("<script"));
        // The style's hash is the one the policy names, so a browser applies it.
        let hash = base64::engine::general_purpose::STANDARD.encode(Sha256::digest(STYLE.as_bytes()));
        assert!(csp().contains(&hash));
        assert!(html.contains(&format!("<style>{STYLE}</style>")));
    }

    #[test]
    fn a_table_shows_the_columns_asked_for() {
        let mut sheet = Sheet::new("vms", "VMs", &[col("Name", 1.0), col("Secret", 1.0), col("vCPU", 1.0)]);
        sheet.push(vec![Cell::text("<b>web01</b>"), Cell::text("x"), Cell::int(2)]);
        let html = table(&sheet, &["vCPU", "Name"]).unwrap();
        assert!(html.contains("<th>vCPU</th><th>Name</th>"), "{html}");
        assert!(
            html.contains("<td class=\"num\">2</td><td>&lt;b&gt;web01&lt;/b&gt;</td>"),
            "{html}"
        );
        assert!(!html.contains("Secret"));
        assert_eq!(table(&Sheet::new("x", "X", &[col("A", 1.0)]), &[]), None);
    }
}
