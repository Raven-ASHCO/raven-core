//! RUP1 decode never allocates above its declared caps
//! (RAVEN_UPDATE_EXCHANGE_V1 §4; `docs/roadmap/plans/phase6-design.json`
//! step P6.48). A counting allocator measures what `update_exchange::decode`
//! allocates on this thread: a refused frame allocates nothing, whatever
//! lengths it declares (a chunk of 2^32 - 1 bytes, 255 offers or path
//! hashes, a 65,535-byte advisory), and an accepted one at most its own
//! payload bytes plus the fixed caps (4 offers of 64-byte targets, 11 path
//! hashes).
//!
//! Its own test binary: the counting allocator is this binary's global
//! allocator, and it counts only while a measurement on this thread runs.

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

use raven_core::update_exchange::{
    decode, encode, Chunk, Have, Offer, Rup1Msg, HEADER_LEN, MAX_FRAME_LEN, NO_REQ_ID, RUP1_MAGIC,
};

struct Counting;

thread_local! {
    static COUNTING: Cell<bool> = const { Cell::new(false) };
    static BYTES: Cell<usize> = const { Cell::new(0) };
    static LARGEST: Cell<usize> = const { Cell::new(0) };
}

fn note(size: usize) {
    // `try_with`: nothing is counted while the thread's locals are torn down.
    let _ = COUNTING.try_with(|on| {
        if on.get() {
            BYTES.with(|b| b.set(b.get() + size));
            LARGEST.with(|l| l.set(l.get().max(size)));
        }
    });
}

// SAFETY: every call is forwarded to the system allocator unchanged; the
// counters are plain thread-local cells that never allocate.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        note(layout.size());
        // SAFETY: the caller's layout, as `GlobalAlloc::alloc` requires.
        unsafe { System.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        note(layout.size());
        // SAFETY: as above.
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        note(new_size);
        // SAFETY: `ptr` and `layout` come from this allocator, as the caller
        // guarantees; `System` allocated them.
        unsafe { System.realloc(ptr, layout, new_size) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: as above.
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static ALLOC: Counting = Counting;

/// What decoding `frame` allocates: (total bytes, largest single
/// allocation, accepted).
fn measure(frame: &[u8]) -> (usize, usize, bool) {
    BYTES.with(|b| b.set(0));
    LARGEST.with(|l| l.set(0));
    COUNTING.with(|on| on.set(true));
    let decoded = decode(frame);
    COUNTING.with(|on| on.set(false));
    let accepted = decoded.is_ok();
    drop(decoded);
    (BYTES.with(Cell::get), LARGEST.with(Cell::get), accepted)
}

fn frame(op: u8, req_id: [u8; 4], body: &[u8]) -> Vec<u8> {
    [&RUP1_MAGIC[..], &[1, op], &req_id, body].concat()
}

const REQ: [u8; 4] = [0x52, 0x55, 0, 1];

#[test]
fn decode_never_allocates_above_the_caps() {
    // Frames that declare far more than they carry, or more than any cap.
    let chunk_head = |index: u32, len: u32| [&index.to_be_bytes()[..], &len.to_be_bytes()].concat();
    let mut refused: Vec<(&str, Vec<u8>)> = vec![
        (
            "chunk of 2^32 - 1 bytes",
            frame(0x85, REQ, &chunk_head(0, u32::MAX)),
        ),
        (
            "chunk of 61,441 bytes",
            frame(0x85, REQ, &[&chunk_head(0, 61_441)[..], &[7; 64]].concat()),
        ),
        (
            "chunk declaring more than it carries",
            frame(0x85, REQ, &[&chunk_head(0, 61_440)[..], &[7; 64]].concat()),
        ),
        (
            "255 path hashes",
            frame(
                0x85,
                REQ,
                &[&chunk_head(0, 1)[..], &[7, 255], &[1; 64]].concat(),
            ),
        ),
        (
            "advisory of 65,535 bytes",
            frame(0x82, REQ, &[0xFF, 0xFF, 1, 2, 3]),
        ),
        (
            "advisory declaring more than it carries",
            frame(0x82, REQ, &[0x80, 0x00, 1, 2, 3]),
        ),
        (
            "manifest of 65,535 bytes",
            frame(0x84, REQ, &[0xFF, 0xFF, 1]),
        ),
        ("empty snapshot", frame(0x83, REQ, &[])),
        (
            "frame over the limit",
            [frame(0x83, REQ, &[]), vec![0; MAX_FRAME_LEN]].concat(),
        ),
    ];
    // A HAVE whose last offer breaks a rule: nothing is copied for the
    // offers before it either.
    let mut have = vec![0u8; 8 + 32 + 4 + 32];
    have.push(4);
    for i in 0..4u8 {
        have.extend(1u64.to_be_bytes());
        have.push(20);
        have.extend_from_slice(b"aarch64-apple-darwin");
        have.extend([i + 1; 32]);
        have.extend(if i == 3 { 0u64 } else { 2_170 }.to_be_bytes());
    }
    refused.push(("HAVE with a bad last offer", frame(0x01, NO_REQ_ID, &have)));
    refused.push((
        "255 offers",
        frame(0x01, NO_REQ_ID, &[&[0u8; 76][..], &[255]].concat()),
    ));
    for (what, f) in &refused {
        let (bytes, _, accepted) = measure(f);
        assert!(!accepted, "{what} was accepted");
        assert_eq!(bytes, 0, "{what}: a refused frame allocated {bytes} bytes");
    }

    // Accepted frames: their own payload bytes plus the fixed caps.
    let target = format!("{}-{}", "a".repeat(31), "b".repeat(32));
    let have = Have {
        adv_serial: 1,
        adv_digest: [1; 32],
        log_size: 3,
        log_root: [2; 32],
        offers: (0..4)
            .map(|i| Offer {
                build_serial: 1,
                target: target.clone(),
                manifest_digest: [i; 32],
                payload_len: 1,
            })
            .collect(),
    };
    let accepted: Vec<(&str, Vec<u8>, usize)> = vec![
        (
            "the longest HAVE",
            encode(&NO_REQ_ID, &Rup1Msg::Have(have)).unwrap(),
            // 4 offers and their targets.
            4 * std::mem::size_of::<Offer>() + 4 * 64,
        ),
        (
            "the longest CHUNK",
            encode(
                &REQ,
                &Rup1Msg::Chunk(Chunk {
                    index: 0,
                    bytes: vec![7; 61_440],
                    path: vec![[9; 32]; 11],
                }),
            )
            .unwrap(),
            61_440 + 11 * 32,
        ),
        (
            "an ADVISORY at the frame limit",
            encode(
                &REQ,
                &Rup1Msg::Advisory {
                    rad1: vec![1; 32_768],
                    snapshot: vec![2; MAX_FRAME_LEN - HEADER_LEN - 2 - 32_768],
                },
            )
            .unwrap(),
            MAX_FRAME_LEN - HEADER_LEN - 2,
        ),
    ];
    for (what, f, cap) in &accepted {
        let (bytes, largest, ok) = measure(f);
        assert!(ok, "{what} was refused");
        // Exactly the payload copies: the counter sees them, and nothing
        // else is allocated.
        assert_eq!(bytes, *cap, "{what}: allocated {bytes} bytes, cap {cap}");
        assert!(
            largest <= f.len(),
            "{what}: one allocation of {largest} bytes"
        );
    }
}
