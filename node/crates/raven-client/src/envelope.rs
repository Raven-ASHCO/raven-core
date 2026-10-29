//! The JSON envelope of desktop/api/API.md: requests in, responses out, and
//! the error codes with their plain-English messages.

use serde_json::{json, Map, Value};

/// The contract version this engine speaks.
pub const VERSION: u64 = 1;

/// The largest request the engine reads (a pasted card is a few hundred
/// bytes, a message at most 64 KiB).
pub const MAX_REQUEST_BYTES: usize = 1 << 20;

/// Error codes (API.md, "Error codes").
pub mod code {
    pub const NOT_INITIALIZED: &str = "NOT_INITIALIZED";
    pub const PROFILE_UNREADABLE: &str = "PROFILE_UNREADABLE";
    pub const PROFILE_LOCKED: &str = "PROFILE_LOCKED";
    pub const KEYCHAIN_DENIED: &str = "KEYCHAIN_DENIED";
    pub const NODE_NOT_RUNNING: &str = "NODE_NOT_RUNNING";
    pub const NOT_A_CONTACT: &str = "NOT_A_CONTACT";
    pub const CONTACT_BLOCKED: &str = "CONTACT_BLOCKED";
    pub const NAME_CLASH: &str = "NAME_CLASH";
    pub const CARD_INVALID: &str = "CARD_INVALID";
    pub const WORDS_INCOMPLETE: &str = "WORDS_INCOMPLETE";
    pub const MESSAGE_TOO_LONG: &str = "MESSAGE_TOO_LONG";
    pub const NOT_SENT_MEET_FIRST: &str = "NOT_SENT_MEET_FIRST";
    pub const TIME_RAN_OUT: &str = "TIME_RAN_OUT";
    pub const NOT_AVAILABLE_YET: &str = "NOT_AVAILABLE_YET";
    pub const BAD_REQUEST: &str = "BAD_REQUEST";
    pub const INTERNAL: &str = "INTERNAL";
    /// A setting that needs the person's yes to what it means first
    /// (`network.set` with `agreed: true`).
    pub const CONSENT_NEEDED: &str = "CONSENT_NEEDED";
    /// `lock.unlock`: that Raven passphrase is not right.
    pub const PASSPHRASE_WRONG: &str = "PASSPHRASE_WRONG";
    /// `lock.unlock`: this profile has a Raven passphrase and none came.
    pub const PASSPHRASE_NEEDED: &str = "PASSPHRASE_NEEDED";
    /// `lock.unlock`: too many wrong passphrases; wait, then try again.
    pub const UNLOCK_WAIT: &str = "UNLOCK_WAIT";
}

/// The default sentence for each code (desktop/design/strings.en.json words
/// where it has them): what happened and one next step.
pub fn default_message(code: &str) -> &'static str {
    match code {
        code::NOT_INITIALIZED => "Raven isn't set up on this computer yet. Finish the setup first.",
        code::PROFILE_UNREADABLE => {
            "Raven can't read its data on this computer. Open Details to see why."
        }
        code::PROFILE_LOCKED => "Raven is locked. Unlock it to continue.",
        code::KEYCHAIN_DENIED => {
            "Raven wasn't allowed to read its keys from the system keychain. Allow access when \
             asked, then try again."
        }
        code::NODE_NOT_RUNNING => {
            "Raven's background program isn't running. Start it from Network, then try again."
        }
        code::NOT_A_CONTACT => "That friend isn't in your list. Add them first.",
        code::CONTACT_BLOCKED => {
            "You blocked this friend on this computer, so nothing goes to them. Unblock them \
             first (raven contact unblock)."
        }
        code::NAME_CLASH => {
            "You already have a friend with this name, or one that looks the same. Pick another \
             name."
        }
        code::CARD_INVALID => {
            "That isn't a Raven invite or card. Ask your friend to send it again."
        }
        code::WORDS_INCOMPLETE => "Type all 10 words, then check again.",
        code::MESSAGE_TOO_LONG => "This message is too long. Split it into shorter messages.",
        code::NOT_SENT_MEET_FIRST => {
            "Not sent: Raven has no secure connection with your friend yet. Send it when you \
             are on the same network."
        }
        code::TIME_RAN_OUT => "Time ran out for this message. Send it again if it still matters.",
        code::NOT_AVAILABLE_YET => "This isn't in this release of Raven yet. Nothing was changed.",
        code::CONSENT_NEEDED => {
            "Raven needs your yes first. Read what this means, then agree to turn it on."
        }
        code::PASSPHRASE_WRONG => "That isn't your Raven passphrase. Try again.",
        code::PASSPHRASE_NEEDED => "Type your Raven passphrase to unlock.",
        code::UNLOCK_WAIT => "Too many wrong passphrases. Wait a little, then try again.",
        code::BAD_REQUEST => {
            "Raven didn't understand what this app asked. Update Raven; if it keeps happening, \
             open Details."
        }
        _ => "Something went wrong inside Raven. Try again; if it keeps happening, open Details.",
    }
}

/// A failure: a code, its plain-English sentence and the technical text
/// (shown only under Details). Both texts are sanitised when the response is
/// built.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiError {
    pub code: &'static str,
    pub message: String,
    pub detail: String,
}

impl ApiError {
    pub fn new(code: &'static str, message: impl Into<String>, detail: impl Into<String>) -> Self {
        ApiError {
            code,
            message: message.into(),
            detail: detail.into(),
        }
    }

    /// `code` with its default sentence.
    pub fn of(code: &'static str, detail: impl Into<String>) -> Self {
        ApiError::new(code, default_message(code), detail)
    }

    pub fn bad_request(detail: impl Into<String>) -> Self {
        ApiError::of(code::BAD_REQUEST, detail)
    }

    pub fn internal(detail: impl Into<String>) -> Self {
        ApiError::of(code::INTERNAL, detail)
    }
}

pub type OpResult = Result<Value, ApiError>;

/// One parsed request.
#[derive(Debug, Clone)]
pub struct Request {
    pub op: String,
    pub args: Map<String, Value>,
}

/// `{"v": 1, "op": "...", "args": {...}}`. `args` may be left out (or null)
/// for operations without arguments; unknown fields are ignored.
pub fn parse_request(text: &str) -> Result<Request, ApiError> {
    if text.len() > MAX_REQUEST_BYTES {
        return Err(ApiError::bad_request(format!(
            "request is {} bytes, more than {MAX_REQUEST_BYTES}",
            text.len()
        )));
    }
    let value: Value = serde_json::from_str(text)
        .map_err(|e| ApiError::bad_request(format!("request is not JSON: {e}")))?;
    let Value::Object(mut map) = value else {
        return Err(ApiError::bad_request("request is not a JSON object"));
    };
    match map.get("v") {
        Some(v) if v.as_u64() == Some(VERSION) => {}
        Some(v) => {
            return Err(ApiError::bad_request(format!(
                "request version {v} is not supported (this engine speaks v{VERSION})"
            )))
        }
        None => return Err(ApiError::bad_request("request has no \"v\"")),
    }
    let op = match map.get("op") {
        Some(Value::String(op)) if !op.is_empty() => op.clone(),
        _ => return Err(ApiError::bad_request("request has no \"op\" string")),
    };
    let args = match map.remove("args") {
        None | Some(Value::Null) => Map::new(),
        Some(Value::Object(args)) => args,
        Some(_) => return Err(ApiError::bad_request("\"args\" must be an object")),
    };
    Ok(Request { op, args })
}

pub fn success(result: Value) -> Value {
    json!({"v": VERSION, "ok": true, "result": result})
}

pub fn failure(e: &ApiError) -> Value {
    json!({
        "v": VERSION,
        "ok": false,
        "error": {"code": e.code, "message": e.message, "detail": e.detail},
    })
}

/// Typed access to a request's `args`; a missing or mistyped field is
/// BAD_REQUEST naming it.
pub struct Args<'a>(pub &'a Map<String, Value>);

impl Args<'_> {
    pub fn str(&self, key: &str) -> Result<&str, ApiError> {
        match self.0.get(key) {
            Some(Value::String(s)) => Ok(s),
            Some(_) => Err(ApiError::bad_request(format!("\"{key}\" must be a string"))),
            None => Err(ApiError::bad_request(format!("\"{key}\" is missing"))),
        }
    }

    pub fn opt_str(&self, key: &str) -> Result<Option<&str>, ApiError> {
        match self.0.get(key) {
            None | Some(Value::Null) => Ok(None),
            Some(Value::String(s)) => Ok(Some(s)),
            Some(_) => Err(ApiError::bad_request(format!("\"{key}\" must be a string"))),
        }
    }

    pub fn opt_bool(&self, key: &str) -> Result<Option<bool>, ApiError> {
        match self.0.get(key) {
            None | Some(Value::Null) => Ok(None),
            Some(Value::Bool(b)) => Ok(Some(*b)),
            Some(_) => Err(ApiError::bad_request(format!(
                "\"{key}\" must be true or false"
            ))),
        }
    }

    pub fn opt_u64(&self, key: &str) -> Result<Option<u64>, ApiError> {
        match self.0.get(key) {
            None | Some(Value::Null) => Ok(None),
            Some(v) => v.as_u64().map(Some).ok_or_else(|| {
                ApiError::bad_request(format!("\"{key}\" must be a whole number of 0 or more"))
            }),
        }
    }

    pub fn has(&self, key: &str) -> bool {
        self.0.contains_key(key)
    }

    pub fn get(&self, key: &str) -> Option<&Value> {
        self.0.get(key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requests_parse_strictly_and_ignore_unknown_fields() {
        let r = parse_request(r#"{"v":1,"op":"app.info","extra":true}"#).unwrap();
        assert_eq!(r.op, "app.info");
        assert!(r.args.is_empty());
        let r = parse_request(r#"{"v":1,"op":"x","args":{"a":"b"}}"#).unwrap();
        assert_eq!(Args(&r.args).str("a").unwrap(), "b");
        for bad in [
            "",
            "null",
            "[]",
            "{}",
            r#"{"op":"app.info"}"#,
            r#"{"v":2,"op":"app.info"}"#,
            r#"{"v":"1","op":"app.info"}"#,
            r#"{"v":1}"#,
            r#"{"v":1,"op":""}"#,
            r#"{"v":1,"op":"x","args":[]}"#,
        ] {
            assert_eq!(
                parse_request(bad).unwrap_err().code,
                code::BAD_REQUEST,
                "{bad}"
            );
        }
    }

    #[test]
    fn every_code_has_one_sentence() {
        for c in [
            code::NOT_INITIALIZED,
            code::PROFILE_UNREADABLE,
            code::PROFILE_LOCKED,
            code::KEYCHAIN_DENIED,
            code::NODE_NOT_RUNNING,
            code::NOT_A_CONTACT,
            code::CONTACT_BLOCKED,
            code::NAME_CLASH,
            code::CARD_INVALID,
            code::WORDS_INCOMPLETE,
            code::MESSAGE_TOO_LONG,
            code::NOT_SENT_MEET_FIRST,
            code::TIME_RAN_OUT,
            code::NOT_AVAILABLE_YET,
            code::BAD_REQUEST,
            code::INTERNAL,
            code::CONSENT_NEEDED,
            code::PASSPHRASE_WRONG,
            code::PASSPHRASE_NEEDED,
            code::UNLOCK_WAIT,
        ] {
            let m = default_message(c);
            assert!(m.ends_with('.') || m.ends_with(')'), "{c}: {m}");
            if c != code::INTERNAL {
                assert_ne!(m, default_message("nonsense"), "{c}");
            }
        }
    }
}
