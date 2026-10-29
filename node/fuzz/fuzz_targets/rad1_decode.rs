#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| raven_fuzz::rad1_decode(data));
