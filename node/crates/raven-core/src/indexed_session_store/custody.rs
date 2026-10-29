//! Friend custody helpers (`docs/design/2026-10-friend-custody.md` §4.2):
//! the profile §6 mailbox store tags of a session, from frozen derivations.
//! Read-only; no schema change.

use super::*;
use crate::atsam_indexed_session::derive_mailbox_tags;

const DAY_MS: u64 = 86_400_000;

/// Which side's mailbox: what we deposit (outbound) or fetch (inbound).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MailboxDirection {
    Inbound,
    Outbound,
}

/// A live session head from SQLite metadata only (no protected load).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionHeadMeta {
    pub key: IndexedSessionRecordKey,
    pub session_id: [u8; 32],
    pub peer_device: [u8; 32],
    pub created_at_ms: u64,
    pub expires_at_ms: u64,
}

/// A Queued ACK row (owed-ACK rebuild after corruption).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueuedAckRow {
    pub session_id: [u8; 32],
    pub object_digest: [u8; 32],
    pub recipient: [u8; 32],
    pub bytes: Vec<u8>,
    pub expires_at_ms: u64,
}

impl IndexedSessionStore {
    /// Unexpired heads involving `local_device`, from metadata only (a
    /// sealed profile's heads opened with K_meta, no protected session
    /// state), newest first.
    pub fn live_session_heads(
        &self,
        local_device: &[u8; 32],
        now_ms: u64,
    ) -> Result<Vec<SessionHeadMeta>, IndexedSessionStoreError> {
        let cutoff = i64::try_from(now_ms).unwrap_or(i64::MAX);
        // Schema 2 (PP.13): the keyed device, the hours that may still be
        // live, then the exact expiry and order from each head's meta.
        let (filter, order, device, bound) = match self.layout.keyed() {
            None => (
                "expires_at_ms > ?1 AND (initiator_device = ?2 OR responder_device = ?2)",
                "created_at_ms DESC, init_id DESC",
                local_device.to_vec(),
                cutoff,
            ),
            // The clear hour at most (no `init_id` column in schema 4):
            // Rust finishes the order below.
            Some(sealer) => (
                "prune_after_hour > ?1 AND (kh_initiator_device = ?2 OR kh_responder_device = ?2)",
                "created_hour DESC",
                sealer.device(local_device).to_vec(),
                crate::sqlite_rebuild::hour_of(now_ms),
            ),
        };
        let mut statement = self.conn.prepare(&format!(
            "SELECT {}, session_id FROM indexed_session_heads WHERE {filter} ORDER BY {order}",
            sealed::head_columns(&self.layout, "")
        ))?;
        let rows = statement.query_map(params![bound, device], |row| {
            Ok((
                sealed::raw_head(&self.layout, row, 0)?,
                row.get::<_, Vec<u8>>(8)?,
            ))
        })?;
        let mut out = Vec::new();
        for row in rows {
            let (raw, sid) = row?;
            let head = match self.layout.head(raw) {
                Ok(head) if head.expires_at_ms <= cutoff => continue,
                Ok(head) => head,
                Err(error @ IndexedSessionStoreError::MetaKeyUnavailable(_)) => return Err(error),
                Err(_) => continue,
            };
            let key = head.key;
            let peer_device = if key.initiator_device_ed25519 == *local_device {
                key.responder_device_ed25519
            } else {
                key.initiator_device_ed25519
            };
            out.push((
                head.created_at_ms,
                SessionHeadMeta {
                    session_id: exact_array(&sid)?,
                    peer_device,
                    created_at_ms: u64::try_from(head.created_at_ms).unwrap_or(0),
                    expires_at_ms: u64::try_from(head.expires_at_ms).unwrap_or(0),
                    key,
                },
            ));
        }
        if self.layout.is_keyed() {
            sealed::newest_first_by(&mut out, |(created, head)| (*created, head.key.init_id));
        }
        Ok(out.into_iter().map(|(_, head)| head).collect())
    }

    /// Store-facing mailbox tags of one Confirmed, unexpired session for each
    /// `day_epochs` entry (one protected load).
    pub fn mailbox_store_tags(
        &mut self,
        key: &IndexedSessionRecordKey,
        direction: MailboxDirection,
        day_epochs: &[u64],
        now_ms: u64,
    ) -> Result<Vec<[u8; 16]>, IndexedSessionStoreError> {
        self.with_confirmed_root(key, now_ms, |root, role| {
            let dir = match direction {
                MailboxDirection::Outbound => role.outbound_direction(),
                MailboxDirection::Inbound => role.inbound_direction(),
            };
            day_epochs
                .iter()
                .map(|day| derive_mailbox_tags(root, day.saturating_mul(DAY_MS), dir).1)
                .collect()
        })
    }

    /// Outbound store tag of one exact object of this session: the day of its
    /// signed `created_at` (deterministic, so a re-deposit is a duplicate).
    pub fn outbound_store_tag_for_object(
        &mut self,
        key: &IndexedSessionRecordKey,
        packed: &[u8],
        now_ms: u64,
    ) -> Result<[u8; 16], IndexedSessionStoreError> {
        let env =
            Envelope::unpack(packed).ok_or(IndexedSessionStoreError::InvalidEndpointEnvelope)?;
        let day = env.created_at / DAY_MS;
        Ok(self.mailbox_store_tags(key, MailboxDirection::Outbound, &[day], now_ms)?[0])
    }

    /// session_id of an ACK row (kind 2) by its object digest (F8 owed ACKs).
    pub fn outbound_session_for_object(
        &self,
        object_digest: &[u8; 32],
    ) -> Result<Option<[u8; 32]>, IndexedSessionStoreError> {
        let raw: Option<Vec<u8>> = self
            .conn
            .query_row(
                &self.layout.ep("SELECT session_id FROM endpoint_outbox
                     WHERE kh_object_digest = ?1 AND kind = 2 LIMIT 1"),
                params![self.layout.ep_digest(object_digest)],
                |row| row.get(0),
            )
            .optional()?;
        raw.map(|v| exact_array(&v)).transpose()
    }

    /// Queued, unexpired ACK rows (owed-ACK rebuild after corruption only).
    pub fn live_queued_ack_rows(
        &self,
        now_ms: u64,
    ) -> Result<Vec<QueuedAckRow>, IndexedSessionStoreError> {
        let rows = super::endpoints::outbox_rows(
            &self.conn,
            &self.layout,
            &format!(
                "SELECT {} FROM endpoint_outbox WHERE kind = 2 AND state = 1",
                super::endpoints::outbox_columns(&self.layout, "")
            ),
            [],
        )?;
        let mut out = Vec::new();
        for row in rows {
            let (sid, digest, recipient, bytes) = (
                row.session_id,
                row.object_digest,
                row.recipient_device,
                row.immutable_envelope_bytes,
            );
            let Some(env) = Envelope::unpack(&bytes) else {
                continue;
            };
            if env.expires_at <= now_ms {
                continue;
            }
            out.push(QueuedAckRow {
                session_id: exact_array(&sid)?,
                object_digest: exact_array(&digest)?,
                recipient: exact_array(&recipient)?,
                bytes,
                expires_at_ms: env.expires_at,
            });
        }
        Ok(out)
    }

    /// Run `f` with the root and local role of a Confirmed, unexpired session.
    fn with_confirmed_root<T>(
        &mut self,
        key: &IndexedSessionRecordKey,
        now_ms: u64,
        f: impl FnOnce(&[u8; 32], LocalRole) -> T,
    ) -> Result<T, IndexedSessionStoreError> {
        let record_key = record_key_digest(key)?;
        let account = hex::encode(record_key);
        let backend = Arc::clone(&self.backend);
        let tx = self.conn.transaction()?;
        let _in_tx = crate::paths::HeldMark::transaction();
        let state = load_and_reconcile(&tx, &self.layout, backend.as_ref(), &account, &record_key)?;
        if state.binding.lifecycle != SessionLifecycle::Confirmed {
            return Err(IndexedSessionStoreError::SessionNotConfirmed);
        }
        if now_ms >= state.binding.expires_at_ms {
            return Err(IndexedSessionStoreError::EndpointNotCurrentlyValid);
        }
        let out = f(&state.ratchets.root, state.binding.local_role);
        drop(state);
        tx.commit()?;
        Ok(out)
    }
}

/// Every day a still-acceptable object of a session can be filed under:
/// `[day(now - MAX_CUSTODY_VALIDITY_MS), day(now + skew)]` within the session's
/// own days (at most 3, usually 2).
pub fn fetch_days(created_at_ms: u64, expires_at_ms: u64, now_ms: u64) -> Vec<u64> {
    let lo = now_ms.saturating_sub(crate::carrier_admission::MAX_CUSTODY_VALIDITY_MS) / DAY_MS;
    let hi = now_ms.saturating_add(MAX_ENDPOINT_FUTURE_SKEW_MS) / DAY_MS;
    let (s_lo, s_hi) = (created_at_ms / DAY_MS, expires_at_ms / DAY_MS);
    (lo.max(s_lo)..=hi.min(s_hi)).collect()
}

/// Days whose inbound tags a recipient registers at a handoff custodian
/// (`RAVEN_CUSTODY_HANDOFF_V1.md` §3.6): yesterday..tomorrow within the
/// session's own days (at most 3). Tomorrow is in, so a tag is registered
/// before any object filed under it exists.
pub fn register_days(created_at_ms: u64, expires_at_ms: u64, now_ms: u64) -> Vec<u64> {
    let today = now_ms / DAY_MS;
    let (lo, hi) = (today.saturating_sub(1), today.saturating_add(1));
    (lo.max(created_at_ms / DAY_MS)..=hi.min(expires_at_ms / DAY_MS)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fetch_days_are_bounded_by_validity_skew_and_session() {
        let day = DAY_MS;
        let now = 100 * day + 3_600_000;
        // A long session: at most three days, usually two.
        let days = fetch_days(90 * day, 110 * day, now);
        assert!(
            days.len() <= 3 && days.contains(&100) && days.contains(&99),
            "{days:?}"
        );
        // Near midnight the skew pulls in tomorrow.
        let late = 101 * day - 60_000;
        assert!(fetch_days(90 * day, 110 * day, late).contains(&101));
        // Clipped to the session's own days.
        assert_eq!(fetch_days(100 * day + 1, 100 * day + 2, now), vec![100]);
    }

    #[test]
    fn register_days_are_yesterday_to_tomorrow_within_the_session() {
        let day = DAY_MS;
        let five_min = 5 * 60_000;
        let long = (90 * day, 110 * day);
        // At most three days, tomorrow included, at any time of the day.
        for now in [100 * day, 100 * day + 3_600_000, 101 * day - 1] {
            assert_eq!(register_days(long.0, long.1, now), vec![99, 100, 101]);
        }
        // Midnight ± 5 min: the window moves by exactly one day.
        assert_eq!(
            register_days(long.0, long.1, 101 * day - five_min),
            vec![99, 100, 101]
        );
        assert_eq!(
            register_days(long.0, long.1, 101 * day + five_min),
            vec![100, 101, 102]
        );
        // Bounded by the session: one that started today and ends
        // tomorrow has no yesterday; one that ends today has no tomorrow.
        let now = 100 * day + 3_600_000;
        assert_eq!(
            register_days(100 * day + 1, 101 * day + 5, now),
            vec![100, 101]
        );
        assert_eq!(
            register_days(90 * day, 100 * day + 7_200_000, now),
            vec![99, 100]
        );
        assert_eq!(register_days(100 * day + 1, 100 * day + 2, now), vec![100]);
        // A session entirely in the past or the future gives none.
        assert!(register_days(90 * day, 95 * day, now).is_empty());
        assert!(register_days(105 * day, 110 * day, now).is_empty());
        // Day 0 does not wrap.
        assert_eq!(register_days(0, 10 * day, 3_600_000), vec![0, 1]);
    }
}
