#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| raven_fuzz::relay_schedule_text(data));
