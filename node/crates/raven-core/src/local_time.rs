//! This computer's local time, for the deadlines Raven shows people (cutoff
//! pack CP.6, M2).
//!
//! std has no time-zone database, so a deadline used to be shown as
//! `14:05 UTC`; in Tehran (UTC+3:30) that invites a wrong meeting time. The
//! offset here comes from the operating system's own rules for the instant
//! asked about (Unix `localtime_r`, Windows `SystemTimeToTzSpecificLocalTime`),
//! so it follows daylight saving time. When it cannot be read, a caller shows
//! only how long is left ("in about 22 h"), never a time on another clock.
//!
//! Display only: nothing Raven stores, signs or decides uses it. Callers pass
//! the time from [`crate::clock::now_ms`]. Tests use
//! [`deadline_with_offsets`]: on glibc `localtime_r` may race with `set_var`
//! in other test threads.

/// Short weekday names, Sunday first (1970-01-01 was a Thursday).
const WEEKDAYS: [&str; 7] = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
/// Short month names, January first.
const MONTHS: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];

/// No zone is further than this from UTC (UTC+14 and UTC-12 are the
/// extremes); an answer beyond it is not believed.
const MAX_OFFSET_S: i32 = 18 * 3600;

const DAY_S: i64 = 86_400;

/// Seconds east of UTC at `at_ms` (Unix ms) from the OS's own rules; None
/// when it cannot be read.
pub fn utc_offset_s(at_ms: u64) -> Option<i32> {
    let at_s = i64::try_from(at_ms / 1000).ok()?;
    os_offset_s(at_s).filter(|off| off.abs() <= MAX_OFFSET_S)
}

/// When something runs out, in this computer's local time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Deadline {
    /// "Tue".
    pub weekday: &'static str,
    /// Day of the month, 1-31.
    pub day: u8,
    /// "Oct".
    pub month: &'static str,
    /// "14:05" (24-hour clock).
    pub hh_mm: String,
    /// How long is left: "in less than a minute", "in about 45 min", "in
    /// about 22 h", "in about 3 days". A time already past reads as "in less
    /// than a minute" (a deadline is never shown in the past).
    pub rel: String,
    /// Calendar days from the local date of `now` to the local date of the
    /// deadline (each on the clock in force at that instant): 0 today, 1
    /// tomorrow, -1 yesterday.
    pub days_ahead: i64,
    /// The fields above but `rel` are this computer's local time. False when
    /// the offset of either instant could not be read: they are then UTC and
    /// must not be shown (`rel` alone is honest).
    pub local: bool,
    /// The offset from UTC (seconds east) the fields are on, while `local`:
    /// what a reader names as the zone (`UTC+1`).
    pub utc_offset_s: Option<i32>,
}

/// [`Deadline`] for `expires_at_ms` seen at `now_ms`, in local time when the
/// OS gives the offset for both instants (each its own: across a daylight
/// saving change they differ).
pub fn deadline(expires_at_ms: u64, now_ms: u64) -> Deadline {
    deadline_with_offsets(
        expires_at_ms,
        now_ms,
        utc_offset_s(expires_at_ms),
        utc_offset_s(now_ms),
    )
}

/// [`deadline`] with one offset for both instants (seconds east of UTC;
/// None: unknown). Pure, for tests of a zone without a daylight saving
/// change in between.
pub fn deadline_with_offset(expires_at_ms: u64, now_ms: u64, off: Option<i32>) -> Deadline {
    deadline_with_offsets(expires_at_ms, now_ms, off, off)
}

/// [`deadline`] with the offsets given: `off_at` at the deadline, `off_now`
/// at `now_ms` (seconds east of UTC; None: unknown). Pure, for tests. The
/// deadline's fields are on its own clock and the days ahead count from
/// today's date on today's clock, so a deadline after a daylight saving
/// change is still "today" or "tomorrow" as the wall calendar says.
pub fn deadline_with_offsets(
    expires_at_ms: u64,
    now_ms: u64,
    off_at: Option<i32>,
    off_now: Option<i32>,
) -> Deadline {
    let at = secs(expires_at_ms) + i64::from(off_at.unwrap_or(0));
    let now = secs(now_ms) + i64::from(off_now.unwrap_or(0));
    let at_day = at.div_euclid(DAY_S);
    let (_, month, day) = civil_from_days(at_day);
    let of_day = at.rem_euclid(DAY_S);
    Deadline {
        weekday: WEEKDAYS[(at_day + 4).rem_euclid(7) as usize],
        day: day as u8,
        month: MONTHS[(month - 1) as usize],
        hh_mm: format!("{:02}:{:02}", of_day / 3600, of_day % 3600 / 60),
        rel: format!("in {}", span_text(expires_at_ms.saturating_sub(now_ms))),
        days_ahead: at_day - now.div_euclid(DAY_S),
        local: off_at.is_some() && off_now.is_some(),
        utc_offset_s: off_at.filter(|_| off_now.is_some()),
    }
}

/// `at_ms` as a UTC time to the second, `2026-10-25T12:43:10Z`: the time at
/// the start of every raven-node log line.
pub fn utc_stamp(at_ms: u64) -> String {
    let s = secs(at_ms);
    let (year, month, day) = civil_from_days(s.div_euclid(DAY_S));
    let of_day = s.rem_euclid(DAY_S);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        of_day / 3600,
        of_day % 3600 / 60,
        of_day % 60
    )
}

/// How long ago `at_ms` was at `now_ms`: "less than a minute ago", "about 45
/// min ago", "about 25 h ago", "about 3 days ago". A time not yet come reads
/// as "less than a minute ago".
pub fn ago_text(at_ms: u64, now_ms: u64) -> String {
    format!("{} ago", span_text(now_ms.saturating_sub(at_ms)))
}

/// "less than a minute", "about 45 min" (under 90 min), "about 22 h" (under
/// two days), "about 3 days".
fn span_text(ms: u64) -> String {
    let minutes = ms / 60_000;
    let hours = (minutes + 30) / 60;
    match minutes {
        0 => "less than a minute".into(),
        1..=89 => format!("about {minutes} min"),
        _ if hours < 48 => format!("about {hours} h"),
        _ => format!("about {} days", (hours + 12) / 24),
    }
}

fn secs(ms: u64) -> i64 {
    i64::try_from(ms / 1000).unwrap_or(i64::MAX / 2)
}

/// (year, month 1-12, day 1-31) of `days` since 1970-01-01 (proleptic
/// Gregorian; H. Hinnant's `civil_from_days`).
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let month = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let year = yoe + era * 400 + i64::from(month <= 2);
    (year, month, day)
}

/// Days since 1970-01-01 of a (year, month 1-12, day) date: the inverse of
/// [`civil_from_days`].
#[cfg(any(windows, test))]
fn days_from_civil(year: i64, month: u32, day: u32) -> i64 {
    let year = year - i64::from(month <= 2);
    let era = year.div_euclid(400);
    let yoe = year.rem_euclid(400);
    let mp = i64::from((month + 9) % 12);
    let doy = (153 * mp + 2) / 5 + i64::from(day) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

#[cfg(unix)]
fn os_offset_s(at_s: i64) -> Option<i32> {
    let t = libc::time_t::try_from(at_s).ok()?;
    let mut tm = std::mem::MaybeUninit::<libc::tm>::uninit();
    // SAFETY: `t` and `tm` live across the call; `localtime_r` is the
    // reentrant form and writes only `tm`, which is read only after it
    // returned non-null (it filled `tm`).
    let gmtoff = unsafe {
        if libc::localtime_r(&t, tm.as_mut_ptr()).is_null() {
            return None;
        }
        tm.assume_init().tm_gmtoff
    };
    i32::try_from(gmtoff).ok()
}

#[cfg(windows)]
fn os_offset_s(at_s: i64) -> Option<i32> {
    use windows_sys::Win32::Foundation::SYSTEMTIME;
    use windows_sys::Win32::System::Time::SystemTimeToTzSpecificLocalTime;
    let day = at_s.div_euclid(DAY_S);
    let of_day = at_s.rem_euclid(DAY_S);
    let (year, month, mday) = civil_from_days(day);
    let utc = SYSTEMTIME {
        wYear: u16::try_from(year).ok()?,
        wMonth: month as u16,
        wDayOfWeek: (day + 4).rem_euclid(7) as u16,
        wDay: mday as u16,
        wHour: (of_day / 3600) as u16,
        wMinute: (of_day % 3600 / 60) as u16,
        wSecond: (of_day % 60) as u16,
        wMilliseconds: 0,
    };
    let mut local = SYSTEMTIME {
        wYear: 0,
        wMonth: 0,
        wDayOfWeek: 0,
        wDay: 0,
        wHour: 0,
        wMinute: 0,
        wSecond: 0,
        wMilliseconds: 0,
    };
    // SAFETY: both SYSTEMTIMEs are plain locals that outlive the call; a null
    // time zone means the one currently active.
    let ok = unsafe { SystemTimeToTzSpecificLocalTime(std::ptr::null(), &utc, &mut local) };
    if ok == 0 {
        return None;
    }
    let local_s = days_from_civil(
        i64::from(local.wYear),
        u32::from(local.wMonth),
        u32::from(local.wDay),
    ) * DAY_S
        + i64::from(local.wHour) * 3600
        + i64::from(local.wMinute) * 60
        + i64::from(local.wSecond);
    i32::try_from(local_s - at_s).ok()
}

#[cfg(not(any(unix, windows)))]
fn os_offset_s(_at_s: i64) -> Option<i32> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 2026-10-20 (a Tuesday) 10:35:00 UTC.
    const TUE_1035_UTC: u64 = 1_792_492_500_000;
    const MIN: u64 = 60_000;
    const HOUR: u64 = 60 * MIN;

    /// E1: raven-node log lines start with this (to the second, UTC).
    #[test]
    fn utc_stamp_is_the_utc_time_to_the_second() {
        assert_eq!(utc_stamp(0), "1970-01-01T00:00:00Z");
        assert_eq!(utc_stamp(TUE_1035_UTC + 7_999), "2026-10-20T10:35:07Z");
        assert_eq!(utc_stamp(951_782_400_000), "2000-02-29T00:00:00Z");
    }

    fn d(expires: u64, now: u64, off: Option<i32>) -> (String, i64, String, String, bool) {
        let d = deadline_with_offset(expires, now, off);
        (
            format!("{} {} {}", d.weekday, d.day, d.month),
            d.days_ahead,
            d.hh_mm,
            d.rel,
            d.local,
        )
    }

    #[test]
    fn local_time_table() {
        let at = TUE_1035_UTC;
        let s = |w: &str, ahead: i64, hh: &str, rel: &str, local: bool| {
            (w.to_string(), ahead, hh.to_string(), rel.to_string(), local)
        };
        // Tehran (UTC+3:30): 14:05 the same day.
        assert_eq!(
            d(at, at - 3 * HOUR, Some(12_600)),
            s("Tue 20 Oct", 0, "14:05", "in about 3 h", true)
        );
        // New York in October (UTC-5): 05:35, and seen the evening before
        // (local Monday 20:35) it is tomorrow.
        assert_eq!(
            d(at, at - 9 * HOUR, Some(-18_000)),
            s("Tue 20 Oct", 1, "05:35", "in about 9 h", true)
        );
        // UTC itself is a known offset.
        assert_eq!(
            d(at, at - 45 * MIN, Some(0)),
            s("Tue 20 Oct", 0, "10:35", "in about 45 min", true)
        );
        // No offset: the fields are UTC and marked not local; only `rel`
        // may be shown.
        assert_eq!(
            d(at, at - 22 * HOUR, None),
            s("Tue 20 Oct", 1, "10:35", "in about 22 h", false)
        );
        // Days ahead count calendar days on the local clock.
        assert_eq!(d(at, at - 6 * 24 * HOUR, Some(12_600)).1, 6);
        assert_eq!(d(at, at - 6 * 24 * HOUR, Some(12_600)).3, "in about 6 days");
        // A deadline already past is never shown in the past.
        assert_eq!(
            d(at, at + 5_000, Some(0)).3,
            "in less than a minute".to_string()
        );
        // Ended yesterday, on the local clock.
        assert_eq!(d(at, at + 20 * HOUR, Some(12_600)).1, -1);
    }

    /// Review C-time-deadlines-3: across a daylight saving change "today"
    /// and "tomorrow" follow the wall calendar. Each instant has its own
    /// offset (Europe/Berlin: CEST +2 h, CET +1 h).
    #[test]
    fn days_ahead_use_each_instants_own_offset() {
        const CEST: i32 = 7_200;
        const CET: i32 = 3_600;
        // 2026-10-24 22:30 UTC = Sun 25 Oct 00:30 CEST; the deadline 09:00
        // UTC = 10:00 CET the same Sunday, after the clocks went back.
        let now = 1_792_881_000_000;
        let at = 1_792_918_800_000;
        let d = deadline_with_offsets(at, now, Some(CET), Some(CEST));
        assert_eq!(
            (d.days_ahead, d.hh_mm.as_str(), d.weekday, d.day),
            (0, "10:00", "Sun", 25)
        );
        assert!(d.local);
        // 2026-03-28 22:30 UTC = Sat 28 Mar 23:30 CET; the deadline 08:00
        // UTC = 10:00 CEST on Sunday, after the clocks went forward.
        let now = 1_774_737_000_000;
        let at = 1_774_771_200_000;
        let d = deadline_with_offsets(at, now, Some(CEST), Some(CET));
        assert_eq!(
            (d.days_ahead, d.hh_mm.as_str(), d.weekday, d.day),
            (1, "10:00", "Sun", 29)
        );
        // Either offset unknown: not local (only `rel` may be shown).
        assert!(!deadline_with_offsets(at, now, Some(CEST), None).local);
        assert!(!deadline_with_offsets(at, now, None, Some(CET)).local);
        // One offset for both is the old single-offset form.
        assert_eq!(
            deadline_with_offset(at, now, Some(CET)),
            deadline_with_offsets(at, now, Some(CET), Some(CET))
        );
    }

    #[test]
    fn spans_and_ago() {
        assert_eq!(span_text(59_999), "less than a minute");
        assert_eq!(span_text(MIN), "about 1 min");
        assert_eq!(span_text(89 * MIN), "about 89 min");
        assert_eq!(span_text(90 * MIN), "about 2 h");
        assert_eq!(span_text(24 * HOUR), "about 24 h");
        assert_eq!(span_text(47 * HOUR), "about 47 h");
        assert_eq!(span_text(48 * HOUR), "about 2 days");
        assert_eq!(ago_text(1_000, 1_000 + 25 * HOUR), "about 25 h ago");
        assert_eq!(ago_text(5_000, 1_000), "less than a minute ago");
    }

    #[test]
    fn civil_dates_round_trip() {
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        assert_eq!(civil_from_days(-1), (1969, 12, 31));
        // 2024-02-29, a leap day.
        assert_eq!(civil_from_days(19_782), (2024, 2, 29));
        for day in (-800_000..800_000).step_by(997) {
            let (y, m, dd) = civil_from_days(day);
            assert_eq!(days_from_civil(y, m, dd), day, "{y}-{m}-{dd}");
        }
    }

    #[test]
    fn the_os_offset_is_whole_and_bounded() {
        // Whatever zone the machine is in, the answer (when there is one) is
        // a plausible offset; Unix CI always has one (UTC at least).
        let off = utc_offset_s(TUE_1035_UTC);
        #[cfg(unix)]
        assert!(off.is_some());
        assert!(off.is_none_or(|o| o.abs() <= MAX_OFFSET_S), "{off:?}");
        let d = deadline(TUE_1035_UTC, TUE_1035_UTC - HOUR);
        assert_eq!(d.local, off.is_some());
        assert!(!d.hh_mm.contains("UTC"));
    }
}
