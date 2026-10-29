//! This build's release serial and advisory floor (design D §1). The
//! release script writes both values in the release commit (P6.46), so a
//! rebuild from a manifest's `source_commit` makes the same binary;
//! development builds keep 0 and no floor. The release form of the floor is
//! `(5, super::hex_bytes::<32>("<the advisory digest, 64 lower-case hex>"))`.

/// This release's build serial (the `build_serial` of its RRB1 manifests);
/// 0 in a development build.
pub const BUILD_SERIAL: u64 = 0;

/// The newest advisory known when this release was built: its serial and
/// its advisory digest. `(0, [0; 32])`: none (a development build).
pub const BUILD_ADVISORY_FLOOR: (u64, [u8; 32]) = (0, [0; 32]);
