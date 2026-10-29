//! RAVEN Release Bundle V1 (RRB1 manifest and RRBC container,
//! `protocol/RAVEN_RELEASE_BUNDLE_V1.md`; `docs/roadmap/plans/phase6-design.json`
//! step P6.43, design D §4 and wire spec W-D3; owner decisions OD6b-25,
//! OD6b-26, OD6b-27): one Raven release for one target triple, signed by 2
//! of the 3 offline release keys and listed in the transparency log.
//!
//! ```text
//! manifest = "RRB1" || 0x01 || kind 0x01 || file_count u8 (1..=16) || reserved 0
//!         || build_serial u64 (>= 1) || created_at_ms u64 || key_set_digest[32]
//!         || version_len u8 (1..=32) || version || target_len u8 (1..=64) || target
//!         || source_commit[20] || toolchain_len u8 (1..=32) || toolchain
//!         || min_advisory_serial u64 || chunk_size u32 (61,440)
//!         || payload_len u64 (1..=67,108,864) || payload_chunk_root[32]
//!         || payload_sha256[32] || files || notes_len u16 (0..=2,048) || notes
//!         || signature block
//! file     = path_len u8 (1..=64) || path || mode u8 (0 = 0644, 1 = 0755)
//!         || offset u64 || size u64 || sha256[32] || rebuild_sha256[32]
//! signing input   = "rvn1/release-manifest/v1\0" || bytes before the block
//! manifest_digest = SHA-256("rvn1/release-manifest/digest/v1\0" || all bytes)
//! container = "RRBC" || 0x01 || reserved[3] 0 || manifest_len u32 || manifest
//!          || snapshot_len u32 || RTL1 snapshot || advisory_len u32
//!          || RAD1 (advisory_len 0: none) || payload (payload_len bytes)
//! ```
//!
//! The payload is the files back to back: in order, without gaps or
//! overlaps, exactly `payload_len` bytes. Paths are relative, at most three
//! segments under `bin/` or `docs/`, and can never leave the directory they
//! are extracted into. The chunk root is RFC 6962 over 61,440-byte chunks
//! (the last one shorter), so a chunk passed along by a friend (RUP1) is
//! checked with its audit path ([`ChunkTree::chunk_path`],
//! [`Manifest::check_chunk`]) before it is written.
//!
//! [`verify_bundle`] checks a decoded bundle in the normative order of spec
//! §7: release keys, the manifest's signatures, the log snapshot (its
//! signatures and root, the manifest listed, consistent with the stored
//! log), the optional advisory, the target, the build serial against the
//! installed one and the release floor, then the chunk root, the payload
//! hash and each file's hash. Pure: no I/O beyond the reader handed to
//! [`Container::open`], no clock. Staging and installing are P6.47's, behind
//! [`SecGate::ReleaseBundle`](crate::security_gate::SecGate::ReleaseBundle)
//! (`RELEASE_BUNDLE_PRODUCTION_ENABLED = false`).

use std::io::{ErrorKind, Read};
use std::ops::Range;

use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::advisory::{Advisory, Rad1Error, MAX_RAD1_LEN};
use crate::identity::Identity;
use crate::release_keys::{KeySet, SigBlock, SigError, KEYSET_MAX_KEYS, SIG_ENTRY_LEN};
use crate::security_events::SecKind;
use crate::tlog::{
    leaf_hash, node_hash, root_of_leaf_hashes, Checked, Consistency, EntryType, LogCheckError,
    LogEntry, Rtl1Error, Snapshot, MAX_SNAPSHOT_LEN,
};

/// The magic of a manifest.
pub const RRB1_MAGIC: &[u8; 4] = b"RRB1";
/// The version byte this revision writes and reads.
pub const RRB1_VERSION: u8 = 0x01;
/// The kind byte of a release manifest.
pub const KIND_MANIFEST: u8 = 0x01;
/// The most files a bundle carries.
pub const MAX_FILES: usize = 16;
/// The longest release version (`1.5.0`).
pub const MAX_VERSION_LEN: usize = 32;
/// The longest target triple (`aarch64-apple-darwin`).
pub const MAX_TARGET_LEN: usize = 64;
/// A git object id (SHA-1).
pub const SOURCE_COMMIT_LEN: usize = 20;
/// The longest toolchain (`1.98.0`).
pub const MAX_TOOLCHAIN_LEN: usize = 32;
/// The only chunk size of version 1: a chunk and its RUP1 frame fit one
/// PAD1 inner frame.
pub const CHUNK_SIZE: u32 = 61_440;
/// The largest payload: 64 MiB.
pub const MAX_PAYLOAD_LEN: u64 = 67_108_864;
/// The most chunks a payload has (64 MiB in 61,440-byte chunks).
pub const MAX_CHUNKS: u64 = MAX_PAYLOAD_LEN.div_ceil(CHUNK_SIZE as u64);
/// The longest chunk audit path (a tree of 1,093 chunks is 11 levels deep).
pub const MAX_CHUNK_PATH_LEN: usize = 11;
/// The longest file path.
pub const MAX_PATH_LEN: usize = 64;
/// The most segments of a file path (`bin/<dir>/<name>`).
pub const MAX_PATH_SEGMENTS: usize = 3;
/// The first segment of every file path.
pub const PATH_ROOTS: [&str; 2] = ["bin", "docs"];
/// The longest release notes (UTF-8 bytes).
pub const MAX_NOTES_LEN: usize = 2_048;
/// A file's fixed fields: path length, mode, offset, size and both hashes.
pub const FILE_FIXED_LEN: usize = 1 + 1 + 8 + 8 + 32 + 32;
/// The manifest's fixed fields: header, serial, time, key set digest, the
/// three length bytes, source commit, advisory serial, chunk size, payload
/// length, both payload hashes and the notes length.
pub const MANIFEST_FIXED_LEN: usize =
    8 + 8 + 8 + 32 + 1 + 1 + SOURCE_COMMIT_LEN + 1 + 8 + 4 + 8 + 32 + 32 + 2;
/// The longest manifest: every field at its maximum and a block of 8
/// signatures (5,198 bytes).
pub const MAX_MANIFEST_LEN: usize = MANIFEST_FIXED_LEN
    + MAX_VERSION_LEN
    + MAX_TARGET_LEN
    + MAX_TOOLCHAIN_LEN
    + MAX_FILES * (FILE_FIXED_LEN + MAX_PATH_LEN)
    + MAX_NOTES_LEN
    + 1
    + SIG_ENTRY_LEN * KEYSET_MAX_KEYS;
/// Domain of [`Manifest::signing_input`].
pub const SIGNING_DOMAIN: &[u8] = b"rvn1/release-manifest/v1\0";
/// Domain of [`Manifest::digest`].
pub const DIGEST_DOMAIN: &[u8] = b"rvn1/release-manifest/digest/v1\0";
/// The magic of a container (`.rrb` file).
pub const RRBC_MAGIC: &[u8; 4] = b"RRBC";
/// The container version byte this revision writes and reads.
pub const RRBC_VERSION: u8 = 0x01;
/// Magic, version and the reserved bytes.
pub const RRBC_HEADER_LEN: usize = 8;
/// The longest container: the header, three length fields, the longest
/// manifest, snapshot and advisory, and the largest payload.
pub const MAX_CONTAINER_LEN: u64 =
    (RRBC_HEADER_LEN + 4 + MAX_MANIFEST_LEN + 4 + MAX_SNAPSHOT_LEN + 4 + MAX_RAD1_LEN) as u64
        + MAX_PAYLOAD_LEN;
/// The target triple this build was compiled for: the only one whose
/// bundles it installs.
pub const THIS_TARGET: &str = env!("RAVEN_BUILD_TARGET");

/// How a file is written when a bundle is staged (spec §3.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum FileMode {
    /// `0`: `0644`, a document.
    Regular,
    /// `1`: `0755`, a program.
    Executable,
}

impl FileMode {
    /// The mode of a mode byte; `None` above 1.
    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            0 => Some(Self::Regular),
            1 => Some(Self::Executable),
            _ => None,
        }
    }

    /// The mode byte.
    pub fn byte(self) -> u8 {
        match self {
            Self::Regular => 0,
            Self::Executable => 1,
        }
    }

    /// The Unix permission bits.
    pub fn unix_mode(self) -> u32 {
        match self {
            Self::Regular => 0o644,
            Self::Executable => 0o755,
        }
    }
}

/// One file of a bundle (spec §3.3): a slice of the payload.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FileEntry {
    /// Relative, `/`-separated, under `bin/` or `docs/` ([`path_well_formed`]).
    pub path: String,
    pub mode: FileMode,
    /// Where the file starts in the payload.
    pub offset: u64,
    pub size: u64,
    /// SHA-256 of the file's bytes.
    pub sha256: [u8; 32],
    /// SHA-256 of the file before platform signing (the reproducible-build
    /// check, OD6b-27); the same as `sha256` for unsigned files.
    pub rebuild_sha256: [u8; 32],
}

impl FileEntry {
    /// The file's bytes in the payload. Decoded manifests keep every file
    /// inside the payload (at most 64 MiB, so it fits a `usize`).
    pub fn range(&self) -> Range<usize> {
        let start = usize::try_from(self.offset).expect("a payload offset fits a usize");
        let len = usize::try_from(self.size).expect("a file size fits a usize");
        start..start + len
    }
}

/// Is `version` a release version (spec §3.2): 1..=32 bytes, three
/// dot-separated runs of digits, then nothing or a `-` or `+` suffix of
/// `[0-9A-Za-z.+-]` (at least one byte after the sign)?
pub fn version_well_formed(version: &str) -> bool {
    if version.is_empty() || version.len() > MAX_VERSION_LEN {
        return false;
    }
    let (core, suffix) = match version.find(['-', '+']) {
        Some(i) => version.split_at(i),
        None => (version, ""),
    };
    let parts: Vec<&str> = core.split('.').collect();
    parts.len() == 3
        && parts
            .iter()
            .all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()))
        && (suffix.is_empty()
            || (suffix.len() > 1
                && suffix
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'+' | b'-'))))
}

/// Is `target` a target triple (spec §3.2): 1..=64 bytes of `[a-z0-9_.-]`,
/// at least two `-`-separated segments, none empty?
pub fn target_well_formed(target: &str) -> bool {
    (1..=MAX_TARGET_LEN).contains(&target.len())
        && target
            .bytes()
            .all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'_' | b'.' | b'-'))
        && target.split('-').count() >= 2
        && target.split('-').all(|s| !s.is_empty())
}

/// Is `toolchain` 1..=32 bytes of `[0-9A-Za-z._+-]` (spec §3.2)?
pub fn toolchain_well_formed(toolchain: &str) -> bool {
    (1..=MAX_TOOLCHAIN_LEN).contains(&toolchain.len())
        && toolchain
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'+' | b'-'))
}

/// Does `segment`'s stem (the part before the first `.`) name a Windows
/// device (`CON`, `PRN`, `AUX`, `NUL`, `COM0`-`COM9`, `LPT0`-`LPT9`, any
/// case)? Such a file opens the device, not a file, on Windows.
fn windows_device(segment: &str) -> bool {
    let stem = segment
        .split('.')
        .next()
        .unwrap_or_default()
        .to_ascii_lowercase();
    match stem.as_bytes() {
        b"con" | b"prn" | b"aux" | b"nul" => true,
        [b'c', b'o', b'm', d] | [b'l', b'p', b't', d] => d.is_ascii_digit(),
        _ => false,
    }
}

/// Is `path` a bundle file path (spec §3.3)? 1..=64 bytes; 2 or 3 segments
/// separated by `/`; the first `bin` or `docs`; each segment non-empty,
/// `[A-Za-z0-9._-]` only, not ending in `.` (so never `.` or `..`, and never
/// a name Windows would shorten), and not a Windows device name. Such a
/// path joined under any directory stays inside it.
pub fn path_well_formed(path: &str) -> bool {
    if path.is_empty() || path.len() > MAX_PATH_LEN {
        return false;
    }
    let segments: Vec<&str> = path.split('/').collect();
    (2..=MAX_PATH_SEGMENTS).contains(&segments.len())
        && PATH_ROOTS.contains(&segments[0])
        && segments.iter().all(|s| {
            !s.is_empty()
                && s.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
                && !s.ends_with('.')
                && !windows_device(s)
        })
}

/// Would two paths name the same file on a case-insensitive file system,
/// or one be a file where the other needs a directory (spec §3.3)?
pub fn paths_collide(a: &str, b: &str) -> bool {
    let (a, b) = (a.to_ascii_lowercase(), b.to_ascii_lowercase());
    let under = |dir: &str, p: &str| {
        p.len() > dir.len() && p.starts_with(dir) && p.as_bytes()[dir.len()] == b'/'
    };
    a == b || under(&a, &b) || under(&b, &a)
}

/// Why manifest bytes are refused (spec §4), in the order they are
/// checked. Each refusal makes the whole manifest, and its bundle, invalid.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum Rrb1Error {
    /// More than [`MAX_MANIFEST_LEN`] bytes.
    #[error("RRB1 TOO_LONG")]
    TooLong,
    /// A field runs past the end.
    #[error("RRB1 TRUNCATED")]
    Truncated,
    /// The bytes do not start with `RRB1`.
    #[error("RRB1 BAD_MAGIC")]
    BadMagic,
    /// The version byte is not [`RRB1_VERSION`].
    #[error("RRB1 BAD_VERSION")]
    BadVersion,
    /// The kind byte is not [`KIND_MANIFEST`].
    #[error("RRB1 BAD_KIND")]
    BadKind,
    /// `file_count` is 0 or more than [`MAX_FILES`].
    #[error("RRB1 BAD_FILE_COUNT")]
    BadFileCount,
    /// The reserved byte is not 0.
    #[error("RRB1 BAD_RESERVED")]
    BadReserved,
    /// `build_serial` is 0.
    #[error("RRB1 BAD_SERIAL")]
    BadSerial,
    /// The release version breaks [`version_well_formed`].
    #[error("RRB1 BAD_RELEASE_VERSION")]
    BadReleaseVersion,
    /// The target triple breaks [`target_well_formed`].
    #[error("RRB1 BAD_TARGET")]
    BadTarget,
    /// The toolchain breaks [`toolchain_well_formed`].
    #[error("RRB1 BAD_TOOLCHAIN")]
    BadToolchain,
    /// `chunk_size` is not [`CHUNK_SIZE`].
    #[error("RRB1 BAD_CHUNK_SIZE")]
    BadChunkSize,
    /// `payload_len` is 0 or more than [`MAX_PAYLOAD_LEN`].
    #[error("RRB1 BAD_PAYLOAD_LEN")]
    BadPayloadLen,
    /// A file path breaks [`path_well_formed`].
    #[error("RRB1 BAD_PATH")]
    BadPath,
    /// A file path collides with an earlier one ([`paths_collide`]).
    #[error("RRB1 DUPLICATE_PATH")]
    DuplicatePath,
    /// A file's mode is above 1.
    #[error("RRB1 BAD_MODE")]
    BadMode,
    /// A file starts before the previous one ends.
    #[error("RRB1 OVERLAP")]
    Overlap,
    /// A file starts after the previous one ends (or the first after 0).
    #[error("RRB1 GAP")]
    Gap,
    /// A file runs past `payload_len`, or the files end before it.
    #[error("RRB1 BAD_COVERAGE")]
    BadCoverage,
    /// `notes_len` is above [`MAX_NOTES_LEN`], or the notes are not UTF-8.
    #[error("RRB1 BAD_NOTES")]
    BadNotes,
    /// The signature block is not exactly `1 + 65 * sig_count` bytes to the
    /// end.
    #[error("RRB1 BAD_SIG_BLOCK")]
    BadSigBlock,
}

impl Rrb1Error {
    /// The name the spec and the vectors use.
    pub fn code(self) -> &'static str {
        match self {
            Self::TooLong => "TOO_LONG",
            Self::Truncated => "TRUNCATED",
            Self::BadMagic => "BAD_MAGIC",
            Self::BadVersion => "BAD_VERSION",
            Self::BadKind => "BAD_KIND",
            Self::BadFileCount => "BAD_FILE_COUNT",
            Self::BadReserved => "BAD_RESERVED",
            Self::BadSerial => "BAD_SERIAL",
            Self::BadReleaseVersion => "BAD_RELEASE_VERSION",
            Self::BadTarget => "BAD_TARGET",
            Self::BadToolchain => "BAD_TOOLCHAIN",
            Self::BadChunkSize => "BAD_CHUNK_SIZE",
            Self::BadPayloadLen => "BAD_PAYLOAD_LEN",
            Self::BadPath => "BAD_PATH",
            Self::DuplicatePath => "DUPLICATE_PATH",
            Self::BadMode => "BAD_MODE",
            Self::Overlap => "OVERLAP",
            Self::Gap => "GAP",
            Self::BadCoverage => "BAD_COVERAGE",
            Self::BadNotes => "BAD_NOTES",
            Self::BadSigBlock => "BAD_SIG_BLOCK",
        }
    }
}

/// Reads fields in order; a field past the end is [`Rrb1Error::Truncated`].
struct Reader<'a> {
    buf: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], Rrb1Error> {
        let end = self.at.checked_add(n).ok_or(Rrb1Error::Truncated)?;
        let out = self.buf.get(self.at..end).ok_or(Rrb1Error::Truncated)?;
        self.at = end;
        Ok(out)
    }

    fn u8(&mut self) -> Result<u8, Rrb1Error> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, Rrb1Error> {
        Ok(u16::from_be_bytes(
            self.take(2)?.try_into().expect("2 bytes"),
        ))
    }

    fn u32(&mut self) -> Result<u32, Rrb1Error> {
        Ok(u32::from_be_bytes(
            self.take(4)?.try_into().expect("4 bytes"),
        ))
    }

    fn u64(&mut self) -> Result<u64, Rrb1Error> {
        Ok(u64::from_be_bytes(
            self.take(8)?.try_into().expect("8 bytes"),
        ))
    }

    fn digest(&mut self) -> Result<[u8; 32], Rrb1Error> {
        Ok(self.take(32)?.try_into().expect("32 bytes"))
    }

    /// A `u8` length (1..=`max`, else `err`), then that many bytes that
    /// must pass `ok` (else `err`).
    fn short_str(
        &mut self,
        max: usize,
        ok: fn(&str) -> bool,
        err: Rrb1Error,
    ) -> Result<&'a str, Rrb1Error> {
        let len = usize::from(self.u8()?);
        if len == 0 || len > max {
            return Err(err);
        }
        std::str::from_utf8(self.take(len)?)
            .ok()
            .filter(|s| ok(s))
            .ok_or(err)
    }
}

/// A decoded release manifest: every structural rule holds (spec §4).
/// Whether it is signed by a key set is [`Manifest::verify`]; whether a
/// payload matches it is [`verify_bundle`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Manifest {
    /// Grows with every release; compared with the installed build's.
    pub build_serial: u64,
    /// When the release was made (Unix ms; shown, never enforced).
    pub created_at_ms: u64,
    /// The key set that signs it ([`KeySet::digest`]).
    pub key_set_digest: [u8; 32],
    /// The release version shown to people (`1.5.0`).
    pub version: String,
    /// The target triple the binaries are for.
    pub target: String,
    /// The git commit the release was built from.
    pub source_commit: [u8; SOURCE_COMMIT_LEN],
    /// The Rust toolchain it was built with.
    pub toolchain: String,
    /// The newest advisory serial when the release was made (0: none):
    /// the release's compiled advisory floor (shown; P6.44).
    pub min_advisory_serial: u64,
    /// Always [`CHUNK_SIZE`].
    pub chunk_size: u32,
    pub payload_len: u64,
    /// RFC 6962 root over the payload's chunks ([`chunk_root`]).
    pub payload_chunk_root: [u8; 32],
    /// SHA-256 of the whole payload.
    pub payload_sha256: [u8; 32],
    /// 1..=16 files, back to back, covering the payload exactly.
    pub files: Vec<FileEntry>,
    /// Release notes (UTF-8, sanitize before showing).
    pub notes: String,
    sigs: SigBlock,
    bytes: Vec<u8>,
    /// Where the signature block starts.
    signed_len: usize,
}

impl Manifest {
    /// Strict decode in the order of spec §4: size, the header and fixed
    /// fields in order, each file in order (path, collision, mode, offset,
    /// size), the coverage, the notes, the signature block to the end.
    pub fn decode(bytes: &[u8]) -> Result<Self, Rrb1Error> {
        if bytes.len() > MAX_MANIFEST_LEN {
            return Err(Rrb1Error::TooLong);
        }
        let mut r = Reader { buf: bytes, at: 0 };
        if r.take(4)? != RRB1_MAGIC {
            return Err(Rrb1Error::BadMagic);
        }
        if r.u8()? != RRB1_VERSION {
            return Err(Rrb1Error::BadVersion);
        }
        if r.u8()? != KIND_MANIFEST {
            return Err(Rrb1Error::BadKind);
        }
        let file_count = usize::from(r.u8()?);
        if file_count == 0 || file_count > MAX_FILES {
            return Err(Rrb1Error::BadFileCount);
        }
        if r.u8()? != 0 {
            return Err(Rrb1Error::BadReserved);
        }
        let build_serial = r.u64()?;
        if build_serial == 0 {
            return Err(Rrb1Error::BadSerial);
        }
        let created_at_ms = r.u64()?;
        let key_set_digest = r.digest()?;
        let version = r.short_str(
            MAX_VERSION_LEN,
            version_well_formed,
            Rrb1Error::BadReleaseVersion,
        )?;
        let target = r.short_str(MAX_TARGET_LEN, target_well_formed, Rrb1Error::BadTarget)?;
        let source_commit = r.take(SOURCE_COMMIT_LEN)?.try_into().expect("20 bytes");
        let toolchain = r.short_str(
            MAX_TOOLCHAIN_LEN,
            toolchain_well_formed,
            Rrb1Error::BadToolchain,
        )?;
        let min_advisory_serial = r.u64()?;
        let chunk_size = r.u32()?;
        if chunk_size != CHUNK_SIZE {
            return Err(Rrb1Error::BadChunkSize);
        }
        let payload_len = r.u64()?;
        if payload_len == 0 || payload_len > MAX_PAYLOAD_LEN {
            return Err(Rrb1Error::BadPayloadLen);
        }
        let payload_chunk_root = r.digest()?;
        let payload_sha256 = r.digest()?;
        let mut files: Vec<FileEntry> = Vec::with_capacity(file_count);
        let mut end = 0u64;
        for _ in 0..file_count {
            let path = r.short_str(MAX_PATH_LEN, path_well_formed, Rrb1Error::BadPath)?;
            if files.iter().any(|f| paths_collide(&f.path, path)) {
                return Err(Rrb1Error::DuplicatePath);
            }
            let mode = FileMode::from_byte(r.u8()?).ok_or(Rrb1Error::BadMode)?;
            let offset = r.u64()?;
            match offset.cmp(&end) {
                std::cmp::Ordering::Less => return Err(Rrb1Error::Overlap),
                std::cmp::Ordering::Greater => return Err(Rrb1Error::Gap),
                std::cmp::Ordering::Equal => {}
            }
            let size = r.u64()?;
            end = offset
                .checked_add(size)
                .filter(|e| *e <= payload_len)
                .ok_or(Rrb1Error::BadCoverage)?;
            let sha256 = r.digest()?;
            let rebuild_sha256 = r.digest()?;
            files.push(FileEntry {
                path: path.to_owned(),
                mode,
                offset,
                size,
                sha256,
                rebuild_sha256,
            });
        }
        if end != payload_len {
            return Err(Rrb1Error::BadCoverage);
        }
        let notes_len = usize::from(r.u16()?);
        if notes_len > MAX_NOTES_LEN {
            return Err(Rrb1Error::BadNotes);
        }
        let notes = std::str::from_utf8(r.take(notes_len)?).map_err(|_| Rrb1Error::BadNotes)?;
        let signed_len = r.at;
        let sigs = SigBlock::decode(&bytes[signed_len..]).map_err(|_| Rrb1Error::BadSigBlock)?;
        Ok(Self {
            build_serial,
            created_at_ms,
            key_set_digest,
            version: version.to_owned(),
            target: target.to_owned(),
            source_commit,
            toolchain: toolchain.to_owned(),
            min_advisory_serial,
            chunk_size,
            payload_len,
            payload_chunk_root,
            payload_sha256,
            files,
            notes: notes.to_owned(),
            sigs,
            bytes: bytes.to_vec(),
            signed_len,
        })
    }

    /// The manifest's bytes, as received.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Where the signature block starts.
    pub fn signed_len(&self) -> usize {
        self.signed_len
    }

    /// The signature block.
    pub fn sigs(&self) -> &SigBlock {
        &self.sigs
    }

    /// What the release keys sign: `"rvn1/release-manifest/v1\0"` and the
    /// bytes before the signature block.
    pub fn signing_input(&self) -> Vec<u8> {
        [SIGNING_DOMAIN, &self.bytes[..self.signed_len]].concat()
    }

    /// `SHA-256("rvn1/release-manifest/digest/v1\0" || all bytes)`: how the
    /// transparency log and RUP1 name this manifest.
    pub fn digest(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(DIGEST_DOMAIN);
        h.update(&self.bytes);
        h.finalize().into()
    }

    /// Signed by `key_set` (spec §7 rules 2-3): it names that key set, and
    /// its signature block passes [`KeySet::verify_sigs`].
    pub fn verify(&self, key_set: &KeySet) -> Result<(), SigError> {
        if self.key_set_digest != key_set.digest() {
            return Err(SigError::WrongKeySet);
        }
        key_set.verify_sigs(&self.signing_input(), &self.sigs)
    }

    /// How many chunks the payload has.
    pub fn chunk_count(&self) -> u64 {
        chunk_count(self.payload_len, self.chunk_size)
    }

    /// The length chunk `index` must have: [`CHUNK_SIZE`], the last one
    /// what is left; `None` past the last chunk.
    pub fn chunk_len(&self, index: u64) -> Option<u64> {
        let start = index.checked_mul(u64::from(self.chunk_size))?;
        (start < self.payload_len)
            .then(|| (self.payload_len - start).min(u64::from(self.chunk_size)))
    }

    /// Is `bytes` chunk `index` of this manifest's payload, by its audit
    /// `path` to the chunk root (spec §5)? Its length must be the chunk's,
    /// and the path at most [`MAX_CHUNK_PATH_LEN`] hashes.
    pub fn check_chunk(&self, index: u64, bytes: &[u8], path: &[[u8; 32]]) -> bool {
        self.chunk_len(index) == Some(bytes.len() as u64)
            && path.len() <= MAX_CHUNK_PATH_LEN
            && verify_chunk_path(
                &self.payload_chunk_root,
                self.chunk_count(),
                index,
                &leaf_hash(bytes),
                path,
            )
    }

    /// The same content, unsigned (to sign again or re-encode).
    pub fn draft(&self) -> ManifestDraft {
        ManifestDraft {
            build_serial: self.build_serial,
            created_at_ms: self.created_at_ms,
            key_set_digest: self.key_set_digest,
            version: self.version.clone(),
            target: self.target.clone(),
            source_commit: self.source_commit,
            toolchain: self.toolchain.clone(),
            min_advisory_serial: self.min_advisory_serial,
            chunk_size: self.chunk_size,
            payload_len: self.payload_len,
            payload_chunk_root: self.payload_chunk_root,
            payload_sha256: self.payload_sha256,
            files: self.files.clone(),
            notes: self.notes.clone(),
        }
    }
}

/// One file to pack ([`ManifestDraft::fill_payload`]).
#[derive(Clone, Copy, Debug)]
pub struct PackFile<'a> {
    pub path: &'a str,
    pub mode: FileMode,
    pub bytes: &'a [u8],
    /// SHA-256 of the file before platform signing.
    pub rebuild_sha256: [u8; 32],
}

/// A manifest before its signatures: what the release tool (P6.46) and the
/// tests build and sign.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ManifestDraft {
    pub build_serial: u64,
    pub created_at_ms: u64,
    pub key_set_digest: [u8; 32],
    pub version: String,
    pub target: String,
    pub source_commit: [u8; SOURCE_COMMIT_LEN],
    pub toolchain: String,
    pub min_advisory_serial: u64,
    pub chunk_size: u32,
    pub payload_len: u64,
    pub payload_chunk_root: [u8; 32],
    pub payload_sha256: [u8; 32],
    pub files: Vec<FileEntry>,
    pub notes: String,
}

impl ManifestDraft {
    /// Set the files, the chunk size, the payload length and both payload
    /// hashes for `files` packed back to back in this order; returns the
    /// payload.
    pub fn fill_payload(&mut self, files: &[PackFile<'_>]) -> Vec<u8> {
        let mut payload = Vec::with_capacity(files.iter().map(|f| f.bytes.len()).sum());
        self.files = files
            .iter()
            .map(|f| {
                let offset = payload.len() as u64;
                payload.extend_from_slice(f.bytes);
                FileEntry {
                    path: f.path.to_owned(),
                    mode: f.mode,
                    offset,
                    size: f.bytes.len() as u64,
                    sha256: Sha256::digest(f.bytes).into(),
                    rebuild_sha256: f.rebuild_sha256,
                }
            })
            .collect();
        self.chunk_size = CHUNK_SIZE;
        self.payload_len = payload.len() as u64;
        self.payload_chunk_root = chunk_root(&payload, CHUNK_SIZE);
        self.payload_sha256 = Sha256::digest(&payload).into();
        payload
    }

    /// The bytes before the signature block, checked by the rules of
    /// [`Manifest::decode`] with an empty block ([`ManifestDraft::assemble`]
    /// checks the size again with the real one).
    pub fn body(&self) -> Result<Vec<u8>, Rrb1Error> {
        let count = u8::try_from(self.files.len()).map_err(|_| Rrb1Error::BadFileCount)?;
        let short = |s: &str, err: Rrb1Error| -> Result<Vec<u8>, Rrb1Error> {
            let len = u8::try_from(s.len()).map_err(|_| err)?;
            Ok([&[len][..], s.as_bytes()].concat())
        };
        let mut out = Vec::with_capacity(MANIFEST_FIXED_LEN + 160 * self.files.len());
        out.extend_from_slice(RRB1_MAGIC);
        out.extend([RRB1_VERSION, KIND_MANIFEST, count, 0]);
        out.extend(self.build_serial.to_be_bytes());
        out.extend(self.created_at_ms.to_be_bytes());
        out.extend(self.key_set_digest);
        out.extend(short(&self.version, Rrb1Error::BadReleaseVersion)?);
        out.extend(short(&self.target, Rrb1Error::BadTarget)?);
        out.extend(self.source_commit);
        out.extend(short(&self.toolchain, Rrb1Error::BadToolchain)?);
        out.extend(self.min_advisory_serial.to_be_bytes());
        out.extend(self.chunk_size.to_be_bytes());
        out.extend(self.payload_len.to_be_bytes());
        out.extend(self.payload_chunk_root);
        out.extend(self.payload_sha256);
        for f in &self.files {
            out.extend(short(&f.path, Rrb1Error::BadPath)?);
            out.push(f.mode.byte());
            out.extend(f.offset.to_be_bytes());
            out.extend(f.size.to_be_bytes());
            out.extend(f.sha256);
            out.extend(f.rebuild_sha256);
        }
        let notes_len = u16::try_from(self.notes.len()).map_err(|_| Rrb1Error::BadNotes)?;
        out.extend(notes_len.to_be_bytes());
        out.extend_from_slice(self.notes.as_bytes());
        let mut check = out.clone();
        check.push(0);
        Manifest::decode(&check)?;
        Ok(out)
    }

    /// What the release keys sign.
    pub fn signing_input(&self) -> Result<Vec<u8>, Rrb1Error> {
        Ok([SIGNING_DOMAIN, &self.body()?[..]].concat())
    }

    /// The manifest with this signature block.
    pub fn assemble(&self, sigs: &SigBlock) -> Result<Manifest, Rrb1Error> {
        let mut bytes = self.body()?;
        bytes.extend(sigs.encode());
        Manifest::decode(&bytes)
    }

    /// The manifest signed by each `(key_index, key)` in order.
    pub fn sign(&self, signers: &[(u8, &Identity)]) -> Result<Manifest, Rrb1Error> {
        self.assemble(&SigBlock::sign(&self.signing_input()?, signers))
    }
}

// ── Chunks (spec §5) ────────────────────────────────────────────────

/// How many chunks of `chunk_size` bytes a payload of `payload_len` bytes
/// has (the last one may be shorter). Panics when `chunk_size` is 0.
pub fn chunk_count(payload_len: u64, chunk_size: u32) -> u64 {
    assert!(chunk_size > 0, "a chunk size is never 0");
    payload_len.div_ceil(u64::from(chunk_size))
}

/// The RFC 6962 leaf hashes of the payload's chunks: `SHA-256(0x00 ||
/// chunk)` for each `chunk_size` bytes, the last chunk what is left. Panics
/// when `chunk_size` is 0.
pub fn chunk_leaf_hashes(payload: &[u8], chunk_size: u32) -> Vec<[u8; 32]> {
    assert!(chunk_size > 0, "a chunk size is never 0");
    let size = usize::try_from(chunk_size).expect("a u32 fits a usize");
    payload.chunks(size).map(leaf_hash).collect()
}

/// The RFC 6962 Merkle tree hash over the payload's chunks: the manifest's
/// `payload_chunk_root`. Panics when `chunk_size` is 0.
pub fn chunk_root(payload: &[u8], chunk_size: u32) -> [u8; 32] {
    root_of_leaf_hashes(&chunk_leaf_hashes(payload, chunk_size))
}

/// The chunk tree of a payload, level by level: what a friend serving the
/// payload over RUP1 sends each chunk's audit path from. Pairing nodes from
/// the left and carrying an unpaired last node up unchanged gives the RFC
/// 6962 tree (split at the largest power of two below the size).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChunkTree {
    /// `levels[0]` the leaf hashes, the last level the root alone.
    levels: Vec<Vec<[u8; 32]>>,
}

impl ChunkTree {
    /// The tree of `payload` in chunks of `chunk_size` bytes.
    pub fn new(payload: &[u8], chunk_size: u32) -> Self {
        Self::of_leaf_hashes(chunk_leaf_hashes(payload, chunk_size))
    }

    /// The tree over these leaf hashes.
    pub fn of_leaf_hashes(leaves: Vec<[u8; 32]>) -> Self {
        let mut levels = vec![leaves];
        while let Some(level) = levels.last().filter(|l| l.len() > 1) {
            let next = level
                .chunks(2)
                .map(|pair| match pair {
                    [left, right] => node_hash(left, right),
                    [one] => *one,
                    _ => unreachable!("chunks(2)"),
                })
                .collect();
            levels.push(next);
        }
        Self { levels }
    }

    /// How many chunks.
    pub fn len(&self) -> usize {
        self.levels[0].len()
    }

    /// No chunks (an empty payload).
    pub fn is_empty(&self) -> bool {
        self.levels[0].is_empty()
    }

    /// The root: [`chunk_root`] of the payload (`SHA-256("")` without
    /// chunks).
    pub fn root(&self) -> [u8; 32] {
        match self.levels.last().map(Vec::as_slice) {
            Some([root]) => *root,
            _ => Sha256::digest([]).into(),
        }
    }

    /// The leaf hash of chunk `index`.
    pub fn leaf(&self, index: usize) -> Option<[u8; 32]> {
        self.levels[0].get(index).copied()
    }

    /// The RFC 6962 §2.1.1 audit path of chunk `index`, from the leaf's
    /// sibling up; `None` past the last chunk.
    pub fn chunk_path(&self, index: usize) -> Option<Vec<[u8; 32]>> {
        if index >= self.len() {
            return None;
        }
        let mut path = Vec::with_capacity(self.levels.len());
        let mut i = index;
        for level in &self.levels[..self.levels.len() - 1] {
            if let Some(sibling) = level.get(i ^ 1) {
                path.push(*sibling);
            }
            i /= 2;
        }
        Some(path)
    }
}

/// Does the audit `path` prove that `leaf` (a chunk's leaf hash) is chunk
/// `index` of a tree of `count` chunks with this `root`? The inclusion
/// check of RFC 9162 §2.1.3.2; a path that is too long or too short fails.
pub fn verify_chunk_path(
    root: &[u8; 32],
    count: u64,
    index: u64,
    leaf: &[u8; 32],
    path: &[[u8; 32]],
) -> bool {
    if index >= count {
        return false;
    }
    let (mut f, mut s) = (index, count - 1);
    let mut r = *leaf;
    for p in path {
        if s == 0 {
            return false;
        }
        if f & 1 == 1 || f == s {
            r = node_hash(p, &r);
            while f & 1 == 0 && f != 0 {
                f >>= 1;
                s >>= 1;
            }
        } else {
            r = node_hash(&r, p);
        }
        f >>= 1;
        s >>= 1;
    }
    s == 0 && r == *root
}

// ── Container (spec §6) ─────────────────────────────────────────────

/// Why container bytes are refused (spec §6), in the order they are read.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum RrbcError {
    /// The input ends inside a field or a part.
    #[error("RRBC TRUNCATED")]
    Truncated,
    /// The input does not start with `RRBC`.
    #[error("RRBC BAD_MAGIC")]
    BadMagic,
    /// The version byte is not [`RRBC_VERSION`].
    #[error("RRBC BAD_VERSION")]
    BadVersion,
    /// A reserved byte is not 0.
    #[error("RRBC BAD_RESERVED")]
    BadReserved,
    /// `manifest_len` is 0 or more than [`MAX_MANIFEST_LEN`].
    #[error("RRBC BAD_MANIFEST_LEN")]
    BadManifestLen,
    /// The manifest is refused (spec §4).
    #[error("RRBC MANIFEST {0}")]
    Manifest(Rrb1Error),
    /// `snapshot_len` is 0 or more than [`MAX_SNAPSHOT_LEN`].
    #[error("RRBC BAD_SNAPSHOT_LEN")]
    BadSnapshotLen,
    /// The log snapshot is refused (RAVEN_TRANSPARENCY_LOG_V1 §5).
    #[error("RRBC SNAPSHOT {0}")]
    Snapshot(Rtl1Error),
    /// `advisory_len` is more than [`MAX_RAD1_LEN`].
    #[error("RRBC BAD_ADVISORY_LEN")]
    BadAdvisoryLen,
    /// The advisory is refused (RAVEN_SECURITY_ADVISORY_V1 §5).
    #[error("RRBC ADVISORY {0}")]
    Advisory(Rad1Error),
    /// Bytes follow the payload.
    #[error("RRBC TRAILING_BYTES")]
    TrailingBytes,
    /// The reader failed (not at its end).
    #[error("RRBC IO {0:?}")]
    Io(ErrorKind),
}

impl RrbcError {
    /// The name the spec and the vectors use.
    pub fn code(self) -> &'static str {
        match self {
            Self::Truncated => "TRUNCATED",
            Self::BadMagic => "BAD_MAGIC",
            Self::BadVersion => "BAD_VERSION",
            Self::BadReserved => "BAD_RESERVED",
            Self::BadManifestLen => "BAD_MANIFEST_LEN",
            Self::Manifest(_) => "MANIFEST",
            Self::BadSnapshotLen => "BAD_SNAPSHOT_LEN",
            Self::Snapshot(_) => "SNAPSHOT",
            Self::BadAdvisoryLen => "BAD_ADVISORY_LEN",
            Self::Advisory(_) => "ADVISORY",
            Self::TrailingBytes => "TRAILING_BYTES",
            Self::Io(_) => "IO",
        }
    }

    /// The refused part's own code (`MANIFEST`, `SNAPSHOT`, `ADVISORY`).
    pub fn inner_code(self) -> Option<&'static str> {
        match self {
            Self::Manifest(e) => Some(e.code()),
            Self::Snapshot(e) => Some(e.code()),
            Self::Advisory(e) => Some(e.code()),
            _ => None,
        }
    }
}

/// The pieces of a bundle (spec §6): from a container ([`Container::open`])
/// or fetched one by one over RUP1. Each piece decoded; nothing verified
/// ([`verify_bundle`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Parts {
    pub manifest: Manifest,
    /// The log snapshot that lists the manifest.
    pub snapshot: Snapshot,
    /// The newest advisory when the bundle was packed, if any.
    pub advisory: Option<Advisory>,
    /// The files back to back.
    pub payload: Vec<u8>,
}

impl Parts {
    /// The container bytes (`.rrb`): a decoded container re-encodes byte
    /// for byte.
    pub fn encode(&self) -> Vec<u8> {
        let manifest = self.manifest.bytes();
        let snapshot = self.snapshot.encode();
        let advisory = self.advisory.as_ref().map_or(&[][..], Advisory::bytes);
        let len = |b: &[u8]| {
            u32::try_from(b.len())
                .expect("parts are capped")
                .to_be_bytes()
        };
        let mut out = Vec::with_capacity(
            RRBC_HEADER_LEN
                + 12
                + manifest.len()
                + snapshot.len()
                + advisory.len()
                + self.payload.len(),
        );
        out.extend_from_slice(RRBC_MAGIC);
        out.extend([RRBC_VERSION, 0, 0, 0]);
        out.extend(len(manifest));
        out.extend_from_slice(manifest);
        out.extend(len(&snapshot));
        out.extend_from_slice(&snapshot);
        out.extend(len(advisory));
        out.extend_from_slice(advisory);
        out.extend_from_slice(&self.payload);
        out
    }
}

/// The `.rrb` container: one file for a USB stick or a download (spec §6).
pub struct Container;

impl Container {
    /// Read and decode a container in the order of spec §6. Each length is
    /// checked against its cap before anything is allocated, a part is read
    /// into exactly its declared length, the payload is exactly the
    /// manifest's `payload_len`, and nothing may follow it.
    pub fn open<R: Read>(mut reader: R) -> Result<Parts, RrbcError> {
        let magic = read_part(&mut reader, 4)?;
        if magic != RRBC_MAGIC {
            return Err(RrbcError::BadMagic);
        }
        if read_part(&mut reader, 1)?[0] != RRBC_VERSION {
            return Err(RrbcError::BadVersion);
        }
        if read_part(&mut reader, 3)? != [0; 3] {
            return Err(RrbcError::BadReserved);
        }
        let manifest_len = read_len(&mut reader)?;
        if manifest_len == 0 || manifest_len > MAX_MANIFEST_LEN {
            return Err(RrbcError::BadManifestLen);
        }
        let manifest = Manifest::decode(&read_part(&mut reader, manifest_len)?)
            .map_err(RrbcError::Manifest)?;
        let snapshot_len = read_len(&mut reader)?;
        if snapshot_len == 0 || snapshot_len > MAX_SNAPSHOT_LEN {
            return Err(RrbcError::BadSnapshotLen);
        }
        let snapshot = Snapshot::decode(&read_part(&mut reader, snapshot_len)?)
            .map_err(RrbcError::Snapshot)?;
        let advisory_len = read_len(&mut reader)?;
        if advisory_len > MAX_RAD1_LEN {
            return Err(RrbcError::BadAdvisoryLen);
        }
        let advisory = match advisory_len {
            0 => None,
            n => Some(Advisory::decode(&read_part(&mut reader, n)?).map_err(RrbcError::Advisory)?),
        };
        let payload_len = usize::try_from(manifest.payload_len).expect("at most 64 MiB");
        let payload = read_part(&mut reader, payload_len)?;
        let mut more = [0u8; 1];
        loop {
            match reader.read(&mut more) {
                Ok(0) => break,
                Ok(_) => return Err(RrbcError::TrailingBytes),
                Err(e) if e.kind() == ErrorKind::Interrupted => continue,
                Err(e) => return Err(RrbcError::Io(e.kind())),
            }
        }
        Ok(Parts {
            manifest,
            snapshot,
            advisory,
            payload,
        })
    }

    /// The container bytes of `parts`.
    pub fn encode(parts: &Parts) -> Vec<u8> {
        parts.encode()
    }
}

/// Exactly `len` bytes (already checked against their cap) into a buffer
/// of exactly that capacity; fewer is [`RrbcError::Truncated`].
fn read_part<R: Read>(reader: &mut R, len: usize) -> Result<Vec<u8>, RrbcError> {
    let mut buf = Vec::with_capacity(len);
    let got = reader
        .take(len as u64)
        .read_to_end(&mut buf)
        .map_err(|e| RrbcError::Io(e.kind()))?;
    if got != len {
        return Err(RrbcError::Truncated);
    }
    Ok(buf)
}

/// A part's `u32` length.
fn read_len<R: Read>(reader: &mut R) -> Result<usize, RrbcError> {
    let b: [u8; 4] = read_part(reader, 4)?.try_into().expect("4 bytes");
    Ok(usize::try_from(u32::from_be_bytes(b)).unwrap_or(usize::MAX))
}

// ── Verification (spec §7) ──────────────────────────────────────────

/// What a bundle is checked against (spec §7).
#[derive(Clone, Copy, Debug)]
pub struct VerifyCtx<'a> {
    /// The release key set this build trusts; `None` (no release keys
    /// until the key ceremony) refuses every bundle.
    pub key_set: Option<&'a KeySet>,
    /// The log entries stored from earlier checked snapshots (empty: none).
    pub stored_log: &'a [LogEntry],
    /// The installed build's serial (0 in development builds).
    pub installed_serial: u64,
    /// This build's target triple ([`THIS_TARGET`]).
    pub target: &'a str,
    /// The stored advisory's release floor (0: none).
    pub release_floor: u64,
    /// The person asked for an older (or the same) build: `--allow-downgrade`
    /// and a typed confirmation (OD6b-26). Never below the release floor.
    pub allow_downgrade: bool,
}

/// Why a decoded bundle is refused (spec §7), in the order checked.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum BundleError {
    /// This build has no release key set: it cannot check updates.
    #[error("RRB1 NO_RELEASE_KEYS")]
    NoReleaseKeys,
    /// The manifest is not signed by the key set (release key sets §2.3);
    /// `WRONG_KEY_SET` also when it names another set and the log does not
    /// list it.
    #[error("RRB1 MANIFEST_SIG {0}")]
    ManifestSig(SigError),
    /// The log snapshot does not check (RAVEN_TRANSPARENCY_LOG_V1 §6.1).
    #[error("RRB1 LOG {0}")]
    Log(LogCheckError),
    /// The log does not list the manifest.
    #[error("RRB1 UNLOGGED")]
    Unlogged,
    /// The log is not a prefix of the stored one, nor the stored one of it.
    #[error("RRB1 SPLIT_VIEW")]
    SplitView,
    /// The advisory is not signed by the key set.
    #[error("RRB1 ADVISORY_SIG {0}")]
    AdvisorySig(SigError),
    /// The log does not list the advisory.
    #[error("RRB1 ADVISORY_UNLOGGED")]
    AdvisoryUnlogged,
    /// The bundle is for another target triple.
    #[error("RRB1 WRONG_TARGET")]
    WrongTarget,
    /// Not newer than the installed build, and no explicit downgrade.
    #[error("RRB1 DOWNGRADE")]
    Downgrade,
    /// Older than the release floor: a build with a known security problem.
    #[error("RRB1 BELOW_FLOOR")]
    BelowFloor,
    /// The payload is not `payload_len` bytes.
    #[error("RRB1 PAYLOAD_LENGTH")]
    PayloadLength,
    /// The payload's chunks do not hash to `payload_chunk_root`.
    #[error("RRB1 BAD_CHUNK_ROOT")]
    BadChunkRoot,
    /// The payload does not hash to `payload_sha256`.
    #[error("RRB1 BAD_PAYLOAD_HASH")]
    BadPayloadHash,
    /// File `n` (0-based) does not hash to its `sha256`.
    #[error("RRB1 BAD_FILE_HASH {0}")]
    BadFileHash(u8),
}

impl BundleError {
    /// The name the spec and the vectors use.
    pub fn code(self) -> &'static str {
        match self {
            Self::NoReleaseKeys => "NO_RELEASE_KEYS",
            Self::ManifestSig(_) => "MANIFEST_SIG",
            Self::Log(_) => "LOG",
            Self::Unlogged => "UNLOGGED",
            Self::SplitView => "SPLIT_VIEW",
            Self::AdvisorySig(_) => "ADVISORY_SIG",
            Self::AdvisoryUnlogged => "ADVISORY_UNLOGGED",
            Self::WrongTarget => "WRONG_TARGET",
            Self::Downgrade => "DOWNGRADE",
            Self::BelowFloor => "BELOW_FLOOR",
            Self::PayloadLength => "PAYLOAD_LENGTH",
            Self::BadChunkRoot => "BAD_CHUNK_ROOT",
            Self::BadPayloadHash => "BAD_PAYLOAD_HASH",
            Self::BadFileHash(_) => "BAD_FILE_HASH",
        }
    }

    /// The signature or log check's own code (`MANIFEST_SIG`, `LOG`,
    /// `ADVISORY_SIG`).
    pub fn inner_code(self) -> Option<&'static str> {
        match self {
            Self::ManifestSig(e) | Self::AdvisorySig(e) => Some(e.code()),
            Self::Log(e) => Some(e.code()),
            _ => None,
        }
    }

    /// The security event a refusal raises (design D sensing points D4,
    /// D5; spec §7.2), attributed to the update and the friend who passed
    /// it on. A missing key set and a wrong target raise none.
    pub fn sec_kind(self) -> Option<SecKind> {
        match self {
            Self::NoReleaseKeys | Self::WrongTarget => None,
            Self::ManifestSig(_)
            | Self::Log(_)
            | Self::PayloadLength
            | Self::BadChunkRoot
            | Self::BadPayloadHash
            | Self::BadFileHash(_) => Some(SecKind::BundleForged),
            Self::AdvisorySig(_) => Some(SecKind::AdvisoryForged),
            Self::Unlogged | Self::AdvisoryUnlogged => Some(SecKind::UpdateUnlogged),
            Self::SplitView => Some(SecKind::LogSplitView),
            Self::Downgrade | Self::BelowFloor => Some(SecKind::BundleDowngrade),
        }
    }
}

/// What vouches for a verified manifest (spec §7.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Authority {
    /// Its own signatures, by the current key set.
    Signed,
    /// It names an earlier key set (rotated out since); the log the current
    /// set signed lists its digest (design D §1).
    Logged,
}

impl Authority {
    /// The name the spec and the vectors use.
    pub fn name(self) -> &'static str {
        match self {
            Self::Signed => "SIGNED",
            Self::Logged => "LOGGED",
        }
    }
}

/// A bundle that passed [`verify_bundle`]: ready to stage (P6.47).
#[derive(Clone, Debug)]
pub struct VerifiedBundle<'a> {
    parts: &'a Parts,
    log: Checked,
    consistency: Consistency,
    authority: Authority,
    release_floor: u64,
}

impl<'a> VerifiedBundle<'a> {
    /// The verified manifest.
    pub fn manifest(&self) -> &'a Manifest {
        &self.parts.manifest
    }

    /// The verified advisory that came with the bundle, if any (the update
    /// state still decides whether it is new: rollback, equivocation).
    pub fn advisory(&self) -> Option<&'a Advisory> {
        self.parts.advisory.as_ref()
    }

    /// The checked log snapshot.
    pub fn log(&self) -> &Checked {
        &self.log
    }

    /// How the bundle's log relates to the stored one (`EXTENDS`: store it).
    pub fn consistency(&self) -> Consistency {
        self.consistency
    }

    /// What vouches for the manifest.
    pub fn authority(&self) -> Authority {
        self.authority
    }

    /// The release floor checked: the stored one, raised by the bundle's
    /// advisory.
    pub fn release_floor(&self) -> u64 {
        self.release_floor
    }

    /// The verified payload.
    pub fn payload(&self) -> &'a [u8] {
        &self.parts.payload
    }

    /// Each file and its verified bytes, in manifest order.
    pub fn files(&self) -> impl Iterator<Item = (&'a FileEntry, &'a [u8])> + 'a {
        let parts = self.parts;
        parts
            .manifest
            .files
            .iter()
            .map(move |f| (f, &parts.payload[f.range()]))
    }
}

/// Verify a decoded bundle in the normative order of spec §7: the release
/// keys, the manifest's signatures, the log (signatures and root, the
/// manifest listed, consistent with `ctx.stored_log`), the optional
/// advisory (signed and listed; its release floor raises `ctx`'s), the
/// target, the build serial (newer than the installed one unless
/// `allow_downgrade`, never below the floor), the payload's length, chunk
/// root and hash, then each file's hash.
pub fn verify_bundle<'a>(
    parts: &'a Parts,
    ctx: &VerifyCtx<'_>,
) -> Result<VerifiedBundle<'a>, BundleError> {
    let key_set = ctx.key_set.ok_or(BundleError::NoReleaseKeys)?;
    let manifest = &parts.manifest;
    let authority = match manifest.verify(key_set) {
        Ok(()) => Authority::Signed,
        Err(SigError::WrongKeySet) => Authority::Logged,
        Err(e) => return Err(BundleError::ManifestSig(e)),
    };
    let log = parts.snapshot.check(key_set).map_err(BundleError::Log)?;
    if !log.contains(EntryType::Manifest, &manifest.digest()) {
        return Err(match authority {
            Authority::Signed => BundleError::Unlogged,
            Authority::Logged => BundleError::ManifestSig(SigError::WrongKeySet),
        });
    }
    let consistency = log.consistency(ctx.stored_log);
    if consistency == Consistency::Split {
        return Err(BundleError::SplitView);
    }
    let mut release_floor = ctx.release_floor;
    if let Some(advisory) = &parts.advisory {
        advisory.verify(key_set).map_err(BundleError::AdvisorySig)?;
        if !log.contains(EntryType::Advisory, &advisory.digest()) {
            return Err(BundleError::AdvisoryUnlogged);
        }
        if let Some(floor) = advisory.entries.iter().find_map(|e| e.release_floor()) {
            release_floor = release_floor.max(floor);
        }
    }
    if manifest.target != ctx.target {
        return Err(BundleError::WrongTarget);
    }
    if manifest.build_serial <= ctx.installed_serial && !ctx.allow_downgrade {
        return Err(BundleError::Downgrade);
    }
    if manifest.build_serial < release_floor {
        return Err(BundleError::BelowFloor);
    }
    if parts.payload.len() as u64 != manifest.payload_len {
        return Err(BundleError::PayloadLength);
    }
    if chunk_root(&parts.payload, manifest.chunk_size) != manifest.payload_chunk_root {
        return Err(BundleError::BadChunkRoot);
    }
    if Sha256::digest(&parts.payload)[..] != manifest.payload_sha256 {
        return Err(BundleError::BadPayloadHash);
    }
    for (i, f) in manifest.files.iter().enumerate() {
        if Sha256::digest(&parts.payload[f.range()])[..] != f.sha256 {
            return Err(BundleError::BadFileHash(
                u8::try_from(i).expect("at most 16 files"),
            ));
        }
    }
    Ok(VerifiedBundle {
        parts,
        log,
        consistency,
        authority,
        release_floor,
    })
}

#[cfg(test)]
mod tests;
