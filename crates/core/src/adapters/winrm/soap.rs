//! SS-12: the WS-Management messages of a remote shell (MS-WSMV, the `windows/shell` resource): Create, Command,
//! Send, Receive, Signal and Delete, written here, and their answers read as untrusted XML (the capped reader of
//! [`crate::convert::describe`]: no DTD, no entity, depth, element and text caps).

use base64::Engine;
use uuid::Uuid;

use crate::convert::describe::{parse_xml_limited, Element, XmlLimits};
use crate::error::{CoreError, Result};

pub const NS_SOAP: &str = "http://www.w3.org/2003/05/soap-envelope";
pub const NS_ADDRESSING: &str = "http://schemas.xmlsoap.org/ws/2004/08/addressing";
pub const NS_WSMAN: &str = "http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd";
pub const NS_WSMAN_MS: &str = "http://schemas.microsoft.com/wbem/wsman/1/wsman.xsd";
pub const NS_SHELL: &str = "http://schemas.microsoft.com/wbem/wsman/1/windows/shell";

/// The cmd shell resource, which runs any program (here `powershell.exe`).
pub const RESOURCE_CMD: &str = "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/cmd";
pub const ACTION_CREATE: &str = "http://schemas.xmlsoap.org/ws/2004/09/transfer/Create";
pub const ACTION_DELETE: &str = "http://schemas.xmlsoap.org/ws/2004/09/transfer/Delete";
pub const ACTION_COMMAND: &str = "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Command";
pub const ACTION_SEND: &str = "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Send";
pub const ACTION_RECEIVE: &str = "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Receive";
pub const ACTION_SIGNAL: &str = "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Signal";
pub const STATE_DONE: &str = "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/CommandState/Done";
pub const SIGNAL_TERMINATE: &str = "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/signal/terminate";
pub const SIGNAL_CTRL_C: &str = "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/signal/ctrl_c";

/// The largest envelope Remotely asks the host to send (WinRM's own default, `MaxEnvelopeSizekb` 150 KB on older
/// Windows; newer ones allow 500).
pub const MAX_ENVELOPE: usize = 153_600;

/// WinRM's code for "no output within the operation timeout": a Receive asks again.
pub const FAULT_TIMED_OUT: &str = "2150858793";

/// What an answer may hold. The body itself is capped by the HTTP layer.
const LIMITS: XmlLimits = XmlLimits {
    depth: 32,
    elements: 2_000,
    text: 512 * 1024,
};

/// `&`, `<`, `>`, `"` and `'` escaped; control characters other than tab, CR and LF dropped (XML 1.0 can't hold them).
pub fn escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            '\t' | '\r' | '\n' => out.push(c),
            c if c.is_control() => {}
            c => out.push(c),
        }
    }
    out
}

/// One message's header fields that change.
pub struct Header<'a> {
    /// The endpoint: `https://host:5986/wsman`.
    pub to: &'a str,
    pub action: &'a str,
    pub shell_id: Option<&'a str>,
    /// `(name, value)` pairs of the `OptionSet`.
    pub options: &'a [(&'a str, &'a str)],
    /// The operation timeout, in seconds.
    pub timeout_secs: u64,
}

/// A whole envelope with `body` (already XML).
pub fn envelope(header: &Header<'_>, body: &str) -> String {
    let selector = header
        .shell_id
        .map(|id| {
            format!(
                "<w:SelectorSet><w:Selector Name=\"ShellId\">{}</w:Selector></w:SelectorSet>",
                escape(id)
            )
        })
        .unwrap_or_default();
    let options = if header.options.is_empty() {
        String::new()
    } else {
        let items: String = header
            .options
            .iter()
            .map(|(name, value)| format!("<w:Option Name=\"{}\">{}</w:Option>", escape(name), escape(value)))
            .collect();
        format!("<w:OptionSet>{items}</w:OptionSet>")
    };
    format!(
        "<s:Envelope xmlns:s=\"{NS_SOAP}\" xmlns:a=\"{NS_ADDRESSING}\" xmlns:w=\"{NS_WSMAN}\" xmlns:p=\"{NS_WSMAN_MS}\" \
xmlns:rsp=\"{NS_SHELL}\"><s:Header><a:To>{to}</a:To><a:ReplyTo><a:Address s:mustUnderstand=\"true\">\
http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</a:Address></a:ReplyTo>\
<w:MaxEnvelopeSize s:mustUnderstand=\"true\">{MAX_ENVELOPE}</w:MaxEnvelopeSize>\
<a:MessageID>uuid:{id}</a:MessageID><w:Locale xml:lang=\"en-US\" s:mustUnderstand=\"false\"/>\
<p:DataLocale xml:lang=\"en-US\" s:mustUnderstand=\"false\"/><w:OperationTimeout>PT{timeout}S</w:OperationTimeout>\
<w:ResourceURI s:mustUnderstand=\"true\">{RESOURCE_CMD}</w:ResourceURI>\
<a:Action s:mustUnderstand=\"true\">{action}</a:Action>{selector}{options}</s:Header><s:Body>{body}</s:Body></s:Envelope>",
        to = escape(header.to),
        id = Uuid::new_v4(),
        timeout = header.timeout_secs.max(1),
        action = escape(header.action),
    )
}

/// Create: a shell with stdin, stdout and stderr, which the host closes after `idle_secs` without use.
pub fn create_body(idle_secs: u64) -> String {
    format!(
        "<rsp:Shell><rsp:InputStreams>stdin</rsp:InputStreams><rsp:OutputStreams>stdout stderr</rsp:OutputStreams>\
<rsp:IdleTimeOut>PT{idle_secs}S</rsp:IdleTimeOut></rsp:Shell>"
    )
}

/// Command: `program` with `arguments` (one line, as the shell gets it).
pub fn command_body(program: &str, arguments: &str) -> String {
    format!(
        "<rsp:CommandLine><rsp:Command>{}</rsp:Command><rsp:Arguments>{}</rsp:Arguments></rsp:CommandLine>",
        escape(program),
        escape(arguments)
    )
}

/// Send: `data` on the command's stdin; `end` closes it.
pub fn send_body(command_id: &str, data: &[u8], end: bool) -> String {
    let end = if end { " End=\"true\"" } else { "" };
    format!(
        "<rsp:Send><rsp:Stream Name=\"stdin\" CommandId=\"{}\"{end}>{}</rsp:Stream></rsp:Send>",
        escape(command_id),
        base64::engine::general_purpose::STANDARD.encode(data)
    )
}

/// Receive: the command's stdout and stderr.
pub fn receive_body(command_id: &str) -> String {
    format!(
        "<rsp:Receive><rsp:DesiredStream CommandId=\"{}\">stdout stderr</rsp:DesiredStream></rsp:Receive>",
        escape(command_id)
    )
}

/// Signal: `code` ([`SIGNAL_TERMINATE`], [`SIGNAL_CTRL_C`]) to the command.
pub fn signal_body(command_id: &str, code: &str) -> String {
    format!(
        "<rsp:Signal CommandId=\"{}\"><rsp:Code>{}</rsp:Code></rsp:Signal>",
        escape(command_id),
        escape(code)
    )
}

/// An answer, read. A SOAP fault becomes [`Answer::Fault`].
#[derive(Debug)]
pub enum Answer {
    Body(Element),
    Fault(Fault),
}

/// A WS-Management fault: WinRM's code (a decimal number, e.g. [`FAULT_TIMED_OUT`]), the subcode and the message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fault {
    pub code: Option<String>,
    pub subcode: Option<String>,
    pub message: String,
}

impl Fault {
    /// A Receive with nothing to give within its operation timeout.
    pub fn timed_out(&self) -> bool {
        self.code.as_deref() == Some(FAULT_TIMED_OUT)
            || self.subcode.as_deref().is_some_and(|s| s.ends_with("TimedOut"))
    }

    pub fn to_error(&self, what: &str) -> CoreError {
        let code = self.code.as_deref().map(|c| format!(" (code {c})")).unwrap_or_default();
        CoreError::Winrm(format!("the host refused {what}: {}{code}", self.message))
    }
}

/// Reads an answer's text: the `Body`'s first element, or its fault.
pub fn read_answer(text: &str) -> Result<Answer> {
    let root = parse_xml_limited(text, LIMITS)
        .ok_or_else(|| CoreError::Winrm("the host's answer is not XML Remotely can read".into()))?;
    if !root.name.eq_ignore_ascii_case("Envelope") {
        return Err(CoreError::Winrm("the host's answer is not a SOAP envelope".into()));
    }
    let body = root
        .child("Body")
        .ok_or_else(|| CoreError::Winrm("the host's answer has no body".into()))?;
    if let Some(fault) = body.child("Fault") {
        return Ok(Answer::Fault(read_fault(fault)));
    }
    Ok(Answer::Body(body.clone()))
}

fn read_fault(fault: &Element) -> Fault {
    let subcode = fault
        .child("Code")
        .and_then(|c| c.child("Subcode"))
        .and_then(|s| s.child("Value"))
        .map(|v| clean(v.text()));
    let mut found = Vec::new();
    fault.find_all("WSManFault", &mut found);
    let code = found.first().and_then(|f| f.attr("Code")).map(clean);
    let mut messages = Vec::new();
    fault.find_all("Message", &mut messages);
    let message = messages
        .first()
        .map(|m| collect_text(m))
        .filter(|m| !m.is_empty())
        .or_else(|| {
            let mut texts = Vec::new();
            fault.find_all("Text", &mut texts);
            texts.first().map(|t| clean(t.text()))
        })
        .unwrap_or_else(|| "no reason given".into());
    Fault { code, subcode, message }
}

/// An element's text and its children's, one line, without control characters, at most 500 characters.
fn collect_text(element: &Element) -> String {
    let mut text = element.text().to_owned();
    for child in &element.children {
        let inner = collect_text(child);
        if !inner.is_empty() {
            if !text.is_empty() {
                text.push(' ');
            }
            text.push_str(&inner);
        }
    }
    clean(&text)
}

/// One line without control or format characters, at most 500 characters (the host's words go into messages).
pub fn clean(text: &str) -> String {
    let one: String = text
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .chars()
        .filter(|c| !c.is_control() && !crate::untrusted::is_format_char(*c))
        .collect();
    let mut out: String = one.chars().take(500).collect();
    if one.chars().count() > 500 {
        out.push('…');
    }
    out
}

/// The shell's id from a Create answer: `rsp:ShellId`, or the `ShellId` selector of the reference it returns.
pub fn shell_id(body: &Element) -> Result<String> {
    let mut ids = Vec::new();
    body.find_all("ShellId", &mut ids);
    let from_element = ids.first().map(|e| e.text().to_owned());
    let from_selector = || {
        let mut selectors = Vec::new();
        body.find_all("Selector", &mut selectors);
        selectors
            .into_iter()
            .find(|s| s.attr("Name").is_some_and(|n| n.eq_ignore_ascii_case("ShellId")))
            .map(|s| s.text().to_owned())
    };
    from_element
        .filter(|id| !id.is_empty())
        .or_else(from_selector)
        .filter(|id| checked_id(id))
        .ok_or_else(|| CoreError::Winrm("the host made a shell but gave no usable shell id".into()))
}

/// The command's id from a Command answer.
pub fn command_id(body: &Element) -> Result<String> {
    let mut ids = Vec::new();
    body.find_all("CommandId", &mut ids);
    ids.first()
        .map(|e| e.text().to_owned())
        .filter(|id| checked_id(id))
        .ok_or_else(|| CoreError::Winrm("the host started the command but gave no usable command id".into()))
}

/// Ids go back into later messages: a GUID's characters only, at most 64.
fn checked_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 64
        && id
            .chars()
            .all(|c| c.is_ascii_hexdigit() || matches!(c, '-' | '{' | '}'))
}

/// What one Receive brought.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Received {
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    /// The command ended, with its exit code when the host gave one.
    pub done: Option<Option<i64>>,
}

/// Reads a Receive answer: each stream's base64 chunks in order, and whether the command is done.
pub fn received(body: &Element, command: &str) -> Result<Received> {
    let mut out = Received::default();
    let mut streams = Vec::new();
    body.find_all("Stream", &mut streams);
    for stream in streams {
        if stream
            .attr("CommandId")
            .is_some_and(|c| !c.eq_ignore_ascii_case(command))
        {
            continue;
        }
        let text: String = stream.text().chars().filter(|c| !c.is_whitespace()).collect();
        if text.is_empty() {
            continue;
        }
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(text.as_bytes())
            .map_err(|_| CoreError::Winrm("the host sent output that is not base64".into()))?;
        match stream.attr("Name") {
            Some(name) if name.eq_ignore_ascii_case("stderr") => out.stderr.extend_from_slice(&bytes),
            _ => out.stdout.extend_from_slice(&bytes),
        }
    }
    let mut states = Vec::new();
    body.find_all("CommandState", &mut states);
    if let Some(state) = states
        .into_iter()
        .find(|s| s.attr("CommandId").is_none_or(|c| c.eq_ignore_ascii_case(command)))
    {
        if state.attr("State").is_some_and(|s| s.eq_ignore_ascii_case(STATE_DONE)) {
            let code = state.child("ExitCode").and_then(|c| c.text().parse::<i64>().ok());
            out.done = Some(code);
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn body_of(text: &str) -> Element {
        match read_answer(text).unwrap() {
            Answer::Body(body) => body,
            Answer::Fault(fault) => panic!("{fault:?}"),
        }
    }

    #[test]
    fn envelopes_hold_the_selector_and_options_escaped() {
        let header = Header {
            to: "https://win01.example.com:5986/wsman",
            action: ACTION_COMMAND,
            shell_id: Some("11111111-2222-3333-4444-555555555555"),
            options: &[("WINRS_SKIP_CMD_SHELL", "TRUE")],
            timeout_secs: 20,
        };
        let text = envelope(&header, &command_body("powershell.exe", "-Command \"a<b\""));
        assert!(text.contains("<w:Selector Name=\"ShellId\">11111111-2222-3333-4444-555555555555</w:Selector>"));
        assert!(text.contains("<w:Option Name=\"WINRS_SKIP_CMD_SHELL\">TRUE</w:Option>"));
        assert!(text.contains("-Command &quot;a&lt;b&quot;"), "{text}");
        assert!(text.contains("<w:OperationTimeout>PT20S</w:OperationTimeout>"));
        // What Remotely writes, it can read.
        assert!(parse_xml_limited(&text, LIMITS).is_some());
    }

    #[test]
    fn answers_give_ids_streams_and_the_exit_code() {
        let created = r#"<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Body>
            <x:ResourceCreated xmlns:x="t"><a:ReferenceParameters><w:SelectorSet>
            <w:Selector Name="ShellId">AAAA-0001</w:Selector></w:SelectorSet></a:ReferenceParameters></x:ResourceCreated>
            </s:Body></s:Envelope>"#;
        assert_eq!(shell_id(&body_of(created)).unwrap(), "AAAA-0001");
        let received_text = r#"<s:Envelope><s:Body><rsp:ReceiveResponse>
            <rsp:Stream Name="stdout" CommandId="C1">aGVsbG8K</rsp:Stream>
            <rsp:Stream Name="stderr" CommandId="C1">b29wcw==</rsp:Stream>
            <rsp:Stream Name="stdout" CommandId="C1" End="true"></rsp:Stream>
            <rsp:CommandState CommandId="C1" State="http://schemas.microsoft.com/wbem/wsman/1/windows/shell/CommandState/Done">
            <rsp:ExitCode>3</rsp:ExitCode></rsp:CommandState></rsp:ReceiveResponse></s:Body></s:Envelope>"#;
        let got = received(&body_of(received_text), "C1").unwrap();
        assert_eq!(got.stdout, b"hello\n");
        assert_eq!(got.stderr, b"oops");
        assert_eq!(got.done, Some(Some(3)));
    }

    #[test]
    fn faults_are_read_and_a_timeout_is_told_apart() {
        let fault = r#"<s:Envelope><s:Body><s:Fault><s:Code><s:Value>s:Receiver</s:Value>
            <s:Subcode><s:Value>w:TimedOut</s:Value></s:Subcode></s:Code>
            <s:Reason><s:Text xml:lang="en-US">The WS-Management service cannot complete the operation within the time specified in OperationTimeout.</s:Text></s:Reason>
            <s:Detail><f:WSManFault Code="2150858793" Machine="win01"><f:Message>timed out</f:Message></f:WSManFault></s:Detail>
            </s:Fault></s:Body></s:Envelope>"#;
        let Answer::Fault(fault) = read_answer(fault).unwrap() else {
            panic!("a fault");
        };
        assert!(fault.timed_out());
        assert_eq!(fault.message, "timed out");
        assert!(fault.to_error("the command").to_string().contains("code 2150858793"));
    }

    #[test]
    fn hostile_answers_are_refused() {
        assert!(read_answer("<!DOCTYPE x [<!ENTITY a \"b\">]><s:Envelope/>").is_err());
        assert!(read_answer("not xml").is_err());
        let deep = format!(
            "<s:Envelope><s:Body>{}{}</s:Body></s:Envelope>",
            "<a>".repeat(40),
            "</a>".repeat(40)
        );
        assert!(read_answer(&deep).is_err());
        // An id that would break the next message is refused.
        let bad = r#"<s:Envelope><s:Body><rsp:CommandResponse><rsp:CommandId>x"/></rsp:CommandId></rsp:CommandResponse></s:Body></s:Envelope>"#;
        assert!(command_id(&body_of(bad)).is_err());
        assert_eq!(clean("a\u{202e}b\n  c\u{7}"), "ab c");
    }
}
