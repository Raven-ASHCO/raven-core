//! What this node left with friends as RAL1 letters (Phase 5b, P5.15;
//! `protocol/RAVEN_ASYNC_LETTER_V1.md`, `RAVEN_FRIEND_CUSTODY_V1.md` §10):
//! one row per letter it sealed, LETTER (messages moved into a letter
//! session, [`crate::horizon::letters`]) or REPLY (a letter session's
//! PairResponse and ACKs), with the exact bytes (the same letter goes to
//! every custodian that serves letters), the custodians that hold it, the
//! last refusal per custodian and when placement is tried again.
//!
//! A letter every custodian refused stays here `unplaced` and its messages
//! stay in their letter session: nothing is lost. Placement is tried again
//! after [`PLACEMENT_RETRY_BASE_MS`], doubling to [`PLACEMENT_RETRY_MAX_MS`]
//! (never past the letter's expiry), and at once after a custodian's RELEASE
//! or a fresh capability answer ([`retry_now`]). A LETTER whose messages all
//! settled (or whose session was given up, [`LetterBook::abandon`]) is
//! withdrawn from its custodians and then forgotten; every row goes at its
//! letter's expiry. So is a LETTER that carries a message the user
//! cancelled ([`cancel_message`]); what else it carried is lettered again.
//!
//! The file is written by raven-node, and by `raven outbox cancel` (which
//! only marks letters to be withdrawn), always under its own lock
//! ([`LETTER_DEPOSITS_LOCK`]). It names contacts (their device keys) and
//! holds letters (ciphertext with both device keys and times in clear), so
//! it is sealed in a sealed profile (RMS1 kind 69, `at_rest::FILES`) and an
//! advisory file otherwise: a file that does not open reads as empty and is
//! never written over.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::at_rest::{self, Advisory, Kind};
use crate::friend_custody::CustodyCode;

/// The file, in the profile folder.
pub const LETTER_DEPOSITS_FILE: &str = "letter_deposits.json";
/// Every writer of [`LETTER_DEPOSITS_FILE`] takes it (`at_rest::FILES`).
pub const LETTER_DEPOSITS_LOCK: &str = ".at_rest.letter_deposits.lock.sqlite";
/// Rows kept at most (the oldest go first): letters are bounded by the
/// letter sessions (one a contact a day, 16 messages each, 7 days).
pub const MAX_LETTER_DEPOSITS: usize = 1024;
/// A letter is left with at most this many custodians (a contact's home
/// custodians are at most two).
pub const MAX_LETTER_CARRIERS: usize = 2;
/// The first wait before a refused letter is offered again ...
pub const PLACEMENT_RETRY_BASE_MS: u64 = 60 * 60 * 1000;
/// ... doubling up to this.
pub const PLACEMENT_RETRY_MAX_MS: u64 = 24 * PLACEMENT_RETRY_BASE_MS;

/// Status codes of a message waiting in a letter (RAVEN_ERROR_CODES_V1,
/// local, status only).
pub mod code {
    /// No custodian holds its letter yet: placement is retried.
    pub const WAITING_FOR_CARRIER: &str = "WAITING_FOR_CARRIER";
    /// Every custodian refused its letter for space (QUOTA, STORE_FULL).
    pub const CARRIER_FULL: &str = "CARRIER_FULL";
    /// No custodian is listed by both sides: it goes when the contact is
    /// reachable.
    pub const NO_SHARED_CARRIER: &str = "NO_SHARED_CARRIER";
}

/// What a row carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DepositKind {
    /// Messages in a letter session this node started (RAL1 kind 1).
    Letter,
    /// The PairResponse and ACKs of a letter session this node accepted
    /// (RAL1 kind 2).
    Reply,
}

/// One letter this node sealed for a custodian to hold.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LetterDeposit {
    #[serde(with = "hex_array")]
    pub digest: [u8; 32],
    pub kind: DepositKind,
    /// The contact it is for (device key).
    #[serde(with = "hex_array")]
    pub peer: [u8; 32],
    #[serde(with = "hex_array")]
    pub session_id: [u8; 32],
    /// The exact RAL1 bytes.
    #[serde(with = "hex_vec")]
    pub letter: Vec<u8>,
    pub created_at_ms: u64,
    pub expires_at_ms: u64,
    /// LETTER: the messages it carries.
    #[serde(default, with = "hex_list")]
    pub message_ids: Vec<[u8; 16]>,
    /// REPLY: the digests of the owed ACKs it carries.
    #[serde(default, with = "hex_list")]
    pub acks: Vec<[u8; 32]>,
    /// The custodians that answered STORED or DUPLICATE.
    #[serde(default, with = "hex_list")]
    pub held_by: Vec<[u8; 32]>,
    /// The last refusal per custodian, by the code's number.
    #[serde(default)]
    pub refused: Vec<Refusal>,
    /// Placement rounds that left it with fewer custodians than it could
    /// have: the backoff.
    #[serde(default)]
    pub tries: u32,
    #[serde(default)]
    pub next_try_ms: u64,
    /// Withdraw it from its custodians (its session was given up).
    #[serde(default)]
    pub withdraw: bool,
}

/// A custodian's refusal of a letter.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Refusal {
    #[serde(with = "hex_array")]
    pub custodian: [u8; 32],
    pub code: u8,
}

impl LetterDeposit {
    /// A new row, not placed anywhere yet (due now).
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        kind: DepositKind,
        peer: [u8; 32],
        session_id: [u8; 32],
        letter: Vec<u8>,
        created_at_ms: u64,
        expires_at_ms: u64,
        message_ids: Vec<[u8; 16]>,
        acks: Vec<[u8; 32]>,
    ) -> Self {
        Self {
            digest: crate::async_letter::letter_digest(&letter),
            kind,
            peer,
            session_id,
            letter,
            created_at_ms,
            expires_at_ms,
            message_ids,
            acks,
            held_by: Vec::new(),
            refused: Vec::new(),
            tries: 0,
            next_try_ms: 0,
            withdraw: false,
        }
    }

    /// Placement is due at `now_ms` with `capable` custodians (that serve
    /// letters) to offer it to: some of them do not hold it, it is not being
    /// withdrawn, and its backoff ran out.
    pub fn placement_due(&self, capable: &[[u8; 32]], now_ms: u64) -> bool {
        !self.withdraw
            && now_ms < self.expires_at_ms
            && self.next_try_ms <= now_ms
            && self.held_by.len() < MAX_LETTER_CARRIERS
            && capable.iter().any(|c| !self.held_by.contains(c))
    }

    /// Record `custodian`'s answer: held, or refused with `code`.
    pub fn note_answer(&mut self, custodian: &[u8; 32], code: CustodyCode) {
        self.refused.retain(|r| r.custodian != *custodian);
        if code.held() {
            if !self.held_by.contains(custodian) {
                self.held_by.push(*custodian);
            }
        } else {
            self.refused.push(Refusal {
                custodian: *custodian,
                code: code as u8,
            });
        }
    }

    /// A placement round ended at `now_ms`: without a custodian holding it,
    /// back off (1 h doubling to 24 h); once one does, offer it to the
    /// others no sooner than the first wait.
    pub fn end_round(&mut self, now_ms: u64) {
        let wait = PLACEMENT_RETRY_BASE_MS
            .saturating_mul(1u64 << self.tries.min(5))
            .min(PLACEMENT_RETRY_MAX_MS);
        self.tries = self.tries.saturating_add(1);
        self.next_try_ms = now_ms.saturating_add(wait);
    }

    /// The status a message in this letter shows while no custodian holds
    /// it: [`code::CARRIER_FULL`] when every custodian refused it for space,
    /// else [`code::WAITING_FOR_CARRIER`]. `None` once one holds it.
    pub fn waiting_code(&self) -> Option<&'static str> {
        if !self.held_by.is_empty() {
            return None;
        }
        let full = |r: &Refusal| {
            matches!(
                CustodyCode::from_u8(r.code),
                CustodyCode::Quota | CustodyCode::StoreFull
            )
        };
        if !self.refused.is_empty() && self.refused.iter().all(full) {
            Some(code::CARRIER_FULL)
        } else {
            Some(code::WAITING_FOR_CARRIER)
        }
    }
}

/// A letter session given up (no PairResponse came back when the contact
/// was reached): no new letter goes into it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AbandonedSession {
    #[serde(with = "hex_array")]
    pub session_id: [u8; 32],
    /// The session's end: forgotten then.
    pub until_ms: u64,
}

/// The file's content.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct LetterBook {
    #[serde(default)]
    pub letters: Vec<LetterDeposit>,
    #[serde(default)]
    pub abandoned: Vec<AbandonedSession>,
}

impl LetterBook {
    /// `peer`'s rows of `kind`.
    pub fn for_peer(
        &self,
        peer: &[u8; 32],
        kind: DepositKind,
    ) -> impl Iterator<Item = &LetterDeposit> {
        let peer = *peer;
        self.letters
            .iter()
            .filter(move |row| row.peer == peer && row.kind == kind)
    }

    /// The LETTER rows that carry `message_id` to `peer` (not withdrawn).
    pub fn carrying(&self, peer: &[u8; 32], message_id: &[u8; 16]) -> Vec<&LetterDeposit> {
        self.for_peer(peer, DepositKind::Letter)
            .filter(|row| !row.withdraw && row.message_ids.contains(message_id))
            .collect()
    }

    /// Every LETTER row that carries `message_id` to `peer`, withdrawn or
    /// not.
    fn carrying_any<'a>(
        &'a self,
        peer: &[u8; 32],
        message_id: &'a [u8; 16],
    ) -> impl Iterator<Item = &'a LetterDeposit> + 'a {
        self.for_peer(peer, DepositKind::Letter)
            .filter(move |row| row.message_ids.contains(message_id))
    }

    /// [`cancel_message`] on the book: mark every LETTER that carries
    /// `message_id` to `peer` to be withdrawn.
    pub fn cancel_message(&mut self, peer: &[u8; 32], message_id: &[u8; 16]) -> CancelledLetters {
        let mut out = CancelledLetters::default();
        for row in self.letters.iter_mut().filter(|row| {
            row.peer == *peer
                && row.kind == DepositKind::Letter
                && row.message_ids.contains(message_id)
        }) {
            out.with_friend |= !row.held_by.is_empty();
            if !row.withdraw {
                row.withdraw = true;
                out.withdrawn += 1;
            }
        }
        out
    }

    /// Was `session_id` given up?
    pub fn is_abandoned(&self, session_id: &[u8; 32]) -> bool {
        self.abandoned.iter().any(|a| a.session_id == *session_id)
    }

    /// Give up the letter session `session_id` (it ends at `until_ms`): its
    /// letters are withdrawn and no new one goes into it.
    pub fn abandon(&mut self, session_id: &[u8; 32], until_ms: u64) {
        if !self.is_abandoned(session_id) {
            self.abandoned.push(AbandonedSession {
                session_id: *session_id,
                until_ms,
            });
        }
        for row in self
            .letters
            .iter_mut()
            .filter(|row| row.session_id == *session_id)
        {
            row.withdraw = true;
        }
    }

    /// Drop what ran out at `now_ms` and keep at most
    /// [`MAX_LETTER_DEPOSITS`] rows (the oldest go).
    fn prune(&mut self, now_ms: u64) {
        self.letters.retain(|row| row.expires_at_ms > now_ms);
        self.abandoned.retain(|a| a.until_ms > now_ms);
        if self.letters.len() > MAX_LETTER_DEPOSITS {
            self.letters.sort_by_key(|row| row.created_at_ms);
            let extra = self.letters.len() - MAX_LETTER_DEPOSITS;
            self.letters.drain(..extra);
        }
    }
}

fn path(data_dir: &Path) -> PathBuf {
    data_dir.join(LETTER_DEPOSITS_FILE)
}

/// The book at `now_ms` (what ran out left out). A missing file, or plain
/// bytes that do not parse, hold nothing; an error when the file could not
/// be read (a sealed one this process cannot open).
pub fn load(data_dir: &Path, now_ms: u64) -> Result<LetterBook, String> {
    match at_rest::load_json_advisory::<LetterBook>(data_dir, &path(data_dir), Kind::LetterDeposits)
    {
        Advisory::Missing | Advisory::CorruptPlain => Ok(LetterBook::default()),
        Advisory::Loaded(mut book) => {
            book.prune(now_ms);
            Ok(book)
        }
        Advisory::Unreadable(e) => Err(format!("{LETTER_DEPOSITS_FILE}: {e}")),
    }
}

/// Change the book under [`LETTER_DEPOSITS_LOCK`]: `edit` sees it pruned at
/// `now_ms`, and it is written back. A file that could not be read is never
/// written over (an error).
pub fn update<R>(
    data_dir: &Path,
    now_ms: u64,
    edit: impl FnOnce(&mut LetterBook) -> R,
) -> Result<R, String> {
    let path = path(data_dir);
    let lock =
        at_rest::lock_file(data_dir, &path, Kind::LetterDeposits).map_err(|e| e.to_string())?;
    let mut book =
        at_rest::load_json_for_write::<LetterBook>(data_dir, &path, Kind::LetterDeposits)
            .map_err(|e| format!("{LETTER_DEPOSITS_FILE}: {e}"))?;
    book.prune(now_ms);
    let out = edit(&mut book);
    book.prune(now_ms);
    lock.store_json(&book).map_err(|e| e.to_string())?;
    Ok(out)
}

/// A custodian released letters or answered a letter op again (fresh
/// capability): every row it does not hold is offered again at once. The
/// contacts whose letters wait (each once); a missing file or none waiting
/// is no write.
pub fn retry_now(
    data_dir: &Path,
    custodian: &[u8; 32],
    now_ms: u64,
) -> Result<Vec<[u8; 32]>, String> {
    let waiting = |row: &LetterDeposit| {
        !row.withdraw && row.next_try_ms > now_ms && !row.held_by.contains(custodian)
    };
    if !load(data_dir, now_ms)?.letters.iter().any(waiting) {
        return Ok(Vec::new());
    }
    update(data_dir, now_ms, |book| {
        let mut peers = Vec::new();
        for row in book.letters.iter_mut().filter(|row| waiting(row)) {
            row.next_try_ms = now_ms;
            if !peers.contains(&row.peer) {
                peers.push(row.peer);
            }
        }
        peers
    })
}

/// What [`cancel_message`] found for a cancelled message.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CancelledLetters {
    /// LETTERs that carried it, now marked to be withdrawn.
    pub withdrawn: usize,
    /// A custodian holds a LETTER that carries it (marked now or before):
    /// the contact may still collect it there before the withdraw arrives.
    pub with_friend: bool,
}

/// `raven outbox cancel` gave up `message_id` to `peer` (re-verify of review
/// 5a-1 and cross-4): every LETTER that carries it is marked to be
/// withdrawn, so it is never offered again and leaves the custodians that
/// hold it on the worker's next pass. The other copies such a letter
/// carried are then carried by no letter, so the worker letters them again
/// without this one (`horizon::letters::reletter`, under the contact's send
/// lock). Run under that lock too. None carrying it is no write.
pub fn cancel_message(
    data_dir: &Path,
    peer: &[u8; 32],
    message_id: &[u8; 16],
    now_ms: u64,
) -> Result<CancelledLetters, String> {
    let book = load(data_dir, now_ms)?;
    if book.carrying_any(peer, message_id).next().is_none() {
        return Ok(CancelledLetters::default());
    }
    update(data_dir, now_ms, |book| {
        book.cancel_message(peer, message_id)
    })
}

/// `custodian` answered a letter op `UNSUPPORTED`: it serves no letter ops
/// now (an older build, letters off there), so what it holds can be neither
/// fetched nor withdrawn. It leaves the holders of every row: no message
/// shows a letter carried there any more, and placement offers the letter
/// to the others. The contacts whose rows changed (each once); none held
/// there is no write.
pub fn forget_holder(
    data_dir: &Path,
    custodian: &[u8; 32],
    now_ms: u64,
) -> Result<Vec<[u8; 32]>, String> {
    let held_there = |row: &LetterDeposit| row.held_by.contains(custodian);
    if !load(data_dir, now_ms)?.letters.iter().any(held_there) {
        return Ok(Vec::new());
    }
    update(data_dir, now_ms, |book| {
        let mut peers = Vec::new();
        for row in book.letters.iter_mut().filter(|row| held_there(row)) {
            row.held_by.retain(|c| c != custodian);
            if !peers.contains(&row.peer) {
                peers.push(row.peer);
            }
        }
        peers
    })
}

mod hex_array {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer, const N: usize>(v: &[u8; N], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(v))
    }

    pub fn deserialize<'de, D: Deserializer<'de>, const N: usize>(
        d: D,
    ) -> Result<[u8; N], D::Error> {
        let s = String::deserialize(d)?;
        let v = hex::decode(&s).map_err(serde::de::Error::custom)?;
        v.try_into()
            .map_err(|_| serde::de::Error::custom("wrong length"))
    }
}

mod hex_vec {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(v))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        hex::decode(&s).map_err(serde::de::Error::custom)
    }
}

mod hex_list {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer, const N: usize>(
        v: &[[u8; N]],
        s: S,
    ) -> Result<S::Ok, S::Error> {
        s.collect_seq(v.iter().map(hex::encode))
    }

    pub fn deserialize<'de, D: Deserializer<'de>, const N: usize>(
        d: D,
    ) -> Result<Vec<[u8; N]>, D::Error> {
        Vec::<String>::deserialize(d)?
            .into_iter()
            .map(|s| {
                hex::decode(&s)
                    .map_err(serde::de::Error::custom)?
                    .try_into()
                    .map_err(|_| serde::de::Error::custom("wrong length"))
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(next_try_ms: u64) -> LetterDeposit {
        let mut row = LetterDeposit::new(
            DepositKind::Letter,
            [1; 32],
            [2; 32],
            vec![0xAB; 40],
            1_000,
            10 * PLACEMENT_RETRY_MAX_MS,
            vec![[3; 16]],
            Vec::new(),
        );
        row.next_try_ms = next_try_ms;
        row
    }

    #[test]
    fn placement_backs_off_one_hour_doubling_to_a_day_and_says_why() {
        let carol = [7u8; 32];
        let dave = [8u8; 32];
        let mut r = row(0);
        assert!(r.placement_due(&[carol], 5));
        assert_eq!(r.waiting_code(), Some(code::WAITING_FOR_CARRIER));
        r.note_answer(&carol, CustodyCode::Quota);
        r.note_answer(&dave, CustodyCode::StoreFull);
        assert_eq!(r.waiting_code(), Some(code::CARRIER_FULL));
        let mut waits = Vec::new();
        for _ in 0..8 {
            r.end_round(0);
            waits.push(r.next_try_ms / PLACEMENT_RETRY_BASE_MS);
        }
        assert_eq!(waits, [1, 2, 4, 8, 16, 24, 24, 24]);
        assert!(!r.placement_due(&[carol], PLACEMENT_RETRY_MAX_MS - 1));
        assert!(r.placement_due(&[carol], PLACEMENT_RETRY_MAX_MS));
        // A refusal for anything but space is a wait, not "full".
        r.note_answer(&dave, CustodyCode::Persistence);
        assert_eq!(r.waiting_code(), Some(code::WAITING_FOR_CARRIER));
        r.note_answer(&carol, CustodyCode::Ok);
        assert_eq!(r.waiting_code(), None);
        assert_eq!(r.held_by, vec![carol]);
        assert!(r.refused.iter().all(|x| x.custodian == dave));
        // Held by every capable custodian: nothing to place.
        assert!(!r.placement_due(&[carol], u64::MAX / 4));
        let json = serde_json::to_string(&r).unwrap();
        assert_eq!(serde_json::from_str::<LetterDeposit>(&json).unwrap(), r);
    }

    #[test]
    fn the_book_prunes_and_retries_at_once_for_a_custodian() {
        crate::identity_store::test_enable_locked_file_identity_backend();
        let dir = tempfile::tempdir().unwrap();
        let carol = [7u8; 32];
        update(dir.path(), 1, |book| {
            book.letters.push(row(5_000));
            let mut gone = row(0);
            gone.expires_at_ms = 2;
            book.letters.push(gone);
        })
        .unwrap();
        let book = load(dir.path(), 3).unwrap();
        assert_eq!(book.letters.len(), 1, "the expired letter went");
        assert_eq!(retry_now(dir.path(), &carol, 10).unwrap(), vec![[1; 32]]);
        assert_eq!(load(dir.path(), 10).unwrap().letters[0].next_try_ms, 10);
        assert!(
            retry_now(dir.path(), &carol, 10).unwrap().is_empty(),
            "already due"
        );
        update(dir.path(), 10, |book| book.abandon(&[2; 32], 50)).unwrap();
        let book = load(dir.path(), 10).unwrap();
        assert!(book.is_abandoned(&[2; 32]) && book.letters[0].withdraw);
        assert!(book.carrying(&[1; 32], &[3; 16]).is_empty());
        assert!(!load(dir.path(), 60).unwrap().is_abandoned(&[2; 32]));
    }

    /// A custodian that turned out to serve no letter ops leaves every
    /// row's holders (review letters-2), the others stay; the contacts
    /// concerned come back once each, and a custodian holding nothing
    /// writes nothing.
    #[test]
    fn a_custodian_without_letters_leaves_every_row() {
        crate::identity_store::test_enable_locked_file_identity_backend();
        let dir = tempfile::tempdir().unwrap();
        let (carol, dave) = ([7u8; 32], [8u8; 32]);
        update(dir.path(), 1, |book| {
            let mut first = row(0);
            first.held_by = vec![carol, dave];
            let mut second = row(0);
            second.letter = vec![0xCD; 40];
            second.digest = crate::async_letter::letter_digest(&second.letter);
            second.held_by = vec![carol];
            let mut other = row(0);
            other.letter = vec![0xEF; 40];
            other.digest = crate::async_letter::letter_digest(&other.letter);
            other.peer = [9; 32];
            other.held_by = vec![dave];
            book.letters.extend([first, second, other]);
        })
        .unwrap();
        assert_eq!(forget_holder(dir.path(), &carol, 2).unwrap(), vec![[1; 32]]);
        let book = load(dir.path(), 2).unwrap();
        let holders: Vec<Vec<[u8; 32]>> =
            book.letters.iter().map(|row| row.held_by.clone()).collect();
        assert_eq!(holders, vec![vec![dave], vec![], vec![dave]]);
        assert_eq!(
            book.letters[1].waiting_code(),
            Some(code::WAITING_FOR_CARRIER)
        );
        assert!(forget_holder(dir.path(), &carol, 3).unwrap().is_empty());
    }

    /// A cancelled message (re-verify of review 5a-1): every LETTER of that
    /// contact that carries it is marked to be withdrawn, and only those;
    /// whether a friend holds one (also one marked before) comes back; a
    /// message no letter carries writes nothing.
    #[test]
    fn a_cancelled_message_withdraws_every_letter_that_carries_it() {
        crate::identity_store::test_enable_locked_file_identity_backend();
        let dir = tempfile::tempdir().unwrap();
        let dd = dir.path();
        let (cancelled, kept, carol) = ([3u8; 16], [4u8; 16], [7u8; 32]);
        let other = |mut r: LetterDeposit, fill: u8| {
            r.letter = vec![fill; 40];
            r.digest = crate::async_letter::letter_digest(&r.letter);
            r
        };
        update(dd, 1, |book| {
            let mut both = row(0);
            both.message_ids = vec![kept, cancelled];
            let alone = other(row(0), 0xC1);
            let only_kept = {
                let mut r = other(row(0), 0xC2);
                r.message_ids = vec![kept];
                r
            };
            let elsewhere = {
                let mut r = other(row(0), 0xC3);
                r.peer = [9; 32];
                r
            };
            let reply = {
                let mut r = other(row(0), 0xC4);
                r.kind = DepositKind::Reply;
                r
            };
            book.letters
                .extend([both, alone, only_kept, elsewhere, reply]);
        })
        .unwrap();
        assert_eq!(
            cancel_message(dd, &[1; 32], &cancelled, 2).unwrap(),
            CancelledLetters {
                withdrawn: 2,
                with_friend: false
            }
        );
        let book = load(dd, 2).unwrap();
        let marked: Vec<bool> = book.letters.iter().map(|r| r.withdraw).collect();
        assert_eq!(marked, vec![true, true, false, false, false]);
        assert!(book.carrying(&[1; 32], &cancelled).is_empty());
        assert_eq!(book.carrying(&[1; 32], &kept).len(), 1, "its own letter");
        // A friend holds one of them: the contact may still collect it.
        update(dd, 3, |book| book.letters[0].held_by = vec![carol]).unwrap();
        assert_eq!(
            cancel_message(dd, &[1; 32], &cancelled, 4).unwrap(),
            CancelledLetters {
                withdrawn: 0,
                with_friend: true
            }
        );
        // Nothing carries it: no write (no file is made either).
        let empty = tempfile::tempdir().unwrap();
        assert_eq!(
            cancel_message(empty.path(), &[1; 32], &cancelled, 4).unwrap(),
            CancelledLetters::default()
        );
        assert!(!empty.path().join(LETTER_DEPOSITS_FILE).exists());
    }

    /// The privacy pack's migration seals the book (kind 69), and later
    /// writes keep it sealed: no contact key or letter byte in clear.
    #[test]
    fn the_book_is_sealed_in_a_sealed_profile() {
        crate::identity_store::test_enable_locked_file_identity_backend();
        let dir = tempfile::tempdir().unwrap();
        let dd = dir.path();
        let now = crate::clock::now_ms();
        let mut kept = row(0);
        kept.expires_at_ms = now + PLACEMENT_RETRY_MAX_MS;
        let first = kept.clone();
        update(dd, now, |book| book.letters.push(first)).unwrap();
        let path = dd.join(LETTER_DEPOSITS_FILE);
        assert!(!at_rest::is_sealed(&std::fs::read(&path).unwrap()));
        std::fs::write(dd.join(crate::BACKEND_MARKER_NAME), b"locked-file\n").unwrap();
        crate::at_rest::tests::expect_key_file(dd);
        let sealed =
            crate::privacy::migrate_all(dd, now, crate::at_rest::MigratePolicy::Allow).unwrap();
        assert_eq!(sealed.outcome, crate::privacy::MigrateOutcome::Sealed);
        let clear = |raw: &[u8]| {
            let peer = hex::encode([1u8; 32]);
            let letter = hex::encode([0xABu8; 40]);
            raw.windows(peer.len()).any(|w| w == peer.as_bytes())
                || raw.windows(letter.len()).any(|w| w == letter.as_bytes())
        };
        let raw = std::fs::read(&path).unwrap();
        assert!(at_rest::is_sealed_as(Kind::LetterDeposits, &raw) && !clear(&raw));
        assert_eq!(load(dd, now).unwrap().letters, vec![kept]);
        update(dd, now, |book| book.letters[0].tries = 3).unwrap();
        let raw = std::fs::read(&path).unwrap();
        assert!(at_rest::is_sealed_as(Kind::LetterDeposits, &raw) && !clear(&raw));
        assert_eq!(load(dd, now).unwrap().letters[0].tries, 3);
    }
}
