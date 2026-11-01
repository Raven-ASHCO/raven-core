// The `ash` and `raven` programs run the whole CLI on the main thread.
// Windows gives a main thread 1 MiB of stack (macOS and Linux give 8 MiB), and
// a debug build of the CLI needs more than that before it prints anything: on
// Windows `raven --version` ended with "thread 'main' has overflowed its
// stack". Ask the Windows linker for the same 8 MiB the other systems give.
use std::env;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    if env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows") {
        return;
    }
    match env::var("CARGO_CFG_TARGET_ENV").as_deref() {
        Ok("msvc") => println!("cargo:rustc-link-arg-bins=/STACK:8388608"),
        Ok("gnu") => println!("cargo:rustc-link-arg-bins=-Wl,--stack,8388608"),
        _ => {}
    }
}
