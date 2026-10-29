//! The C ABI (include/raven_client.h): `raven_call` and `raven_free`.
//!
//! - Never returns NULL: a NULL or non-UTF-8 request is answered with a
//!   `BAD_REQUEST` envelope, a panic with `INTERNAL`.
//! - Every returned string is allocated here and must be given back to
//!   [`raven_free`] (and nothing else).

use std::ffi::{c_char, CStr, CString};
use std::panic::AssertUnwindSafe;

use crate::envelope::{self, ApiError};
use crate::LAST_RESORT;

/// A response as a C string; a response with a NUL byte (it can't have one:
/// JSON escapes it) falls back to the last-resort error.
fn to_c(response: String) -> *mut c_char {
    CString::new(response)
        .or_else(|_| CString::new(LAST_RESORT))
        .map(CString::into_raw)
        .unwrap_or(std::ptr::null_mut())
}

fn bad_request(detail: &str) -> String {
    serde_json::to_string(&envelope::failure(&ApiError::bad_request(detail)))
        .unwrap_or_else(|_| LAST_RESORT.to_owned())
}

/// One request envelope (NUL-terminated UTF-8 JSON) in, one response out.
/// Thread-safe; may block. Free the result with [`raven_free`].
///
/// # Safety
/// `request_json` is NULL or points to a NUL-terminated string that stays
/// valid for the duration of the call.
#[no_mangle]
pub unsafe extern "C" fn raven_call(request_json: *const c_char) -> *mut c_char {
    let answer = std::panic::catch_unwind(AssertUnwindSafe(|| {
        if request_json.is_null() {
            return bad_request("the request is NULL");
        }
        // SAFETY: not NULL, and the caller promises a NUL-terminated string
        // that outlives this call.
        let raw = unsafe { CStr::from_ptr(request_json) };
        match raw.to_str() {
            Ok(text) => crate::call(text),
            Err(_) => bad_request("the request is not UTF-8"),
        }
    }))
    .unwrap_or_else(|_| LAST_RESORT.to_owned());
    let out = to_c(answer);
    if out.is_null() {
        // Unreachable (LAST_RESORT has no NUL byte); keep the promise anyway.
        return CString::default().into_raw();
    }
    out
}

/// Frees a string returned by [`raven_call`]. NULL is ignored.
///
/// # Safety
/// `response` is NULL or a pointer [`raven_call`] returned that was not
/// freed yet.
#[no_mangle]
pub unsafe extern "C" fn raven_free(response: *mut c_char) {
    if response.is_null() {
        return;
    }
    let _ = std::panic::catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: the caller hands back a pointer from CString::into_raw in
        // raven_call, exactly once.
        drop(unsafe { CString::from_raw(response) });
    }));
}
