//! Append-only audit log writer with fail-closed write semantics.
//!
//! Record construction and durable append are one critical section. Sequence
//! allocation, predecessor lookup, hash construction (by the caller-supplied
//! builder), JSONL write, sync, and head advancement cannot race with another
//! request. A write failure halts the writer until the process is restarted.

use parking_lot::Mutex;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::models::AuditEntry;
use crate::{AuraError, Result};

/// Thread-safe audit-log writer.
///
/// Cloning produces another handle to the same underlying state and file.
/// Every committed entry receives its sequence and predecessor while holding
/// the writer mutex, so concurrent callers cannot construct competing heads.
#[derive(Clone)]
pub struct LogWriter {
    inner: Arc<Inner>,
}

struct Inner {
    path: PathBuf,
    state: Mutex<WriterState>,
}

struct WriterState {
    file: Option<File>,
    next_seq: u64,
    last_chain: String,
    halted: bool,
}

impl LogWriter {
    /// Open (or create) the JSONL audit log and replay the existing chain head.
    pub fn open(path: PathBuf, genesis: &str) -> Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| {
                AuraError::LogWrite(format!(
                    "cannot create log directory '{}': {e}",
                    parent.display()
                ))
            })?;
        }

        // Replay the existing file to find the next sequence and chain head.
        let (next_seq, head_chain) = if path.exists() {
            replay_head(&path, genesis)?
        } else {
            (0u64, genesis.to_string())
        };

        let file = OpenOptions::new()
            .append(true)
            .create(true)
            .open(&path)
            .map_err(|e| {
                AuraError::LogWrite(format!("cannot open log '{}': {e}", path.display()))
            })?;

        Ok(Self {
            inner: Arc::new(Inner {
                path,
                state: Mutex::new(WriterState {
                    file: Some(file),
                    next_seq,
                    last_chain: head_chain,
                    halted: false,
                }),
            }),
        })
    }

    /// Return the next sequence value as a diagnostic snapshot.
    ///
    /// Do not use this to construct an entry. Request-path code must use
    /// [`append_with`] so sequence and predecessor are captured atomically.
    pub fn next_seq(&self) -> u64 {
        self.inner.state.lock().next_seq
    }

    /// Return the committed chain head as a diagnostic snapshot.
    ///
    /// Do not use this to construct an entry. Request-path code must use
    /// [`append_with`] so sequence and predecessor are captured atomically.
    pub fn current_head(&self) -> String {
        self.inner.state.lock().last_chain.clone()
    }

    /// Build, append, and durably commit one entry under a single writer lock.
    ///
    /// The builder receives the only valid next sequence number and the current
    /// committed predecessor. It must return the complete entry, including its
    /// hash computed from those values. The lock remains held through JSONL
    /// serialization, write, sync, and head advancement.
    pub fn append_with<F>(&self, build: F) -> Result<AuditEntry>
    where
        F: FnOnce(u64, &str) -> AuditEntry,
    {
        self.append_with_observer(build, |_| {})
    }

    /// Build, append, and durably commit one entry under a single writer lock,
    /// then invoke `after_commit` before allowing another append to proceed.
    ///
    /// The callback is the ordered hand-off point for dependent append-side
    /// state, such as the segment sealer. It runs after the JSONL line is
    /// synced and the writer head has advanced, but while the writer mutex is
    /// still held. The callback must not attempt to append through this writer.
    pub(crate) fn append_with_observer<F, O>(&self, build: F, after_commit: O) -> Result<AuditEntry>
    where
        F: FnOnce(u64, &str) -> AuditEntry,
        O: FnOnce(&AuditEntry),
    {
        let mut state = self.inner.state.lock();
        if state.halted {
            return Err(self.halted_error());
        }

        let seq = state.next_seq;
        let prev_hash = state.last_chain.clone();
        let entry = build(seq, &prev_hash);

        if entry.seq != seq || entry.prev_hash != prev_hash {
            return Err(AuraError::LogWrite(
                "entry builder changed the reserved sequence or predecessor".into(),
            ));
        }

        Self::append_locked(&self.inner.path, &mut state, &entry)?;
        after_commit(&entry);
        Ok(entry)
    }

    /// Append a pre-built entry only if it still matches the current head.
    ///
    /// Kept for callers that already construct entries. Stale entries are
    /// rejected rather than written into a forked chain. New request-path code
    /// should prefer [`append_with`].
    pub fn append(&self, entry: &AuditEntry) -> Result<()> {
        let mut state = self.inner.state.lock();
        if state.halted {
            return Err(self.halted_error());
        }

        if entry.seq != state.next_seq || entry.prev_hash != state.last_chain {
            return Err(AuraError::LogWrite(format!(
                "stale audit entry rejected: expected seq {} with prev_hash {}, got seq {} with prev_hash {}",
                state.next_seq, state.last_chain, entry.seq, entry.prev_hash
            )));
        }

        Self::append_locked(&self.inner.path, &mut state, entry)
    }

    fn append_locked(path: &Path, state: &mut WriterState, entry: &AuditEntry) -> Result<()> {
        // Reserve capacity for the following sequence before writing, so an
        // integer overflow cannot leave a committed entry without a successor.
        let following_seq = entry
            .seq
            .checked_add(1)
            .ok_or_else(|| AuraError::LogWrite("audit sequence exhausted at u64::MAX".into()))?;

        let line = serde_json::to_string(entry).map_err(AuraError::Json)?;
        let write_result = match state.file.as_mut() {
            Some(file) => writeln!(file, "{line}").and_then(|()| file.sync_data()),
            None => {
                state.halted = true;
                return Err(AuraError::LogWrite(
                    "audit log file handle was closed".into(),
                ));
            }
        };

        if let Err(e) = write_result {
            state.halted = true;
            return Err(AuraError::LogWrite(format!(
                "write/sync failed for log '{}': {e}",
                path.display()
            )));
        }

        state.last_chain = entry.chain_hash.clone();
        state.next_seq = following_seq;
        Ok(())
    }

    fn halted_error(&self) -> AuraError {
        AuraError::LogWrite(format!(
            "audit log halted (file '{}' previously failed to write)",
            self.inner.path.display()
        ))
    }

    /// Whether the writer is in the halted (fail-closed) state.
    pub fn is_halted(&self) -> bool {
        self.inner.state.lock().halted
    }
}

/// Re-read the existing log to find the next sequence and head chain_hash.
fn replay_head(path: &Path, genesis: &str) -> Result<(u64, String)> {
    let raw = std::fs::read_to_string(path).map_err(|e| {
        AuraError::LogWrite(format!(
            "cannot read existing log '{}': {e}",
            path.display()
        ))
    })?;
    let mut last_seq: Option<u64> = None;
    let mut head_chain = genesis.to_string();
    for line in raw.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let entry: AuditEntry = serde_json::from_str(line).map_err(|e| {
            AuraError::LogWrite(format!(
                "log corrupt — cannot parse entry: {e}; line='{}'",
                &line[..line.len().min(80)]
            ))
        })?;
        last_seq = Some(entry.seq);
        head_chain = entry.chain_hash;
    }
    let next_seq = last_seq
        .map(|s| {
            s.checked_add(1)
                .ok_or_else(|| AuraError::LogWrite("audit sequence exhausted at u64::MAX".into()))
        })
        .transpose()?
        .unwrap_or(0);
    Ok((next_seq, head_chain))
}

/// Parse a JSONL audit log into structured entries. Used by `aura-replay`.
pub fn read_all_entries(path: &Path) -> Result<Vec<AuditEntry>> {
    let raw = std::fs::read_to_string(path).map_err(|e| AuraError::PolicyRead {
        path: path.display().to_string(),
        source: e,
    })?;
    let mut entries = Vec::new();
    for (i, line) in raw.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let entry: AuditEntry = serde_json::from_str(line).map_err(|e| AuraError::PolicyParse {
            path: path.display().to_string(),
            message: format!("line {} not valid JSON: {e}", i + 1),
        })?;
        entries.push(entry);
    }
    Ok(entries)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::chain::{compute_chain_hash, verify_chain};
    use crate::crypto::{genesis_hash, sha256_hex};
    use crate::models::AuditEntry;
    use std::sync::{Arc, Barrier};

    fn build_entry(seq: u64, prev_hash: &str, worker: usize, iteration: usize) -> AuditEntry {
        let timestamp = "2026-10-14T00:00:00+00:00".to_string();
        let decision = "ALLOW".to_string();
        let policy_set = "stress-test".to_string();
        let policy_hash = "a".repeat(64);
        let context = format!("worker-{worker}-iteration-{iteration}");
        let input_hash = sha256_hex(&format!("input-{worker}-{iteration}"));
        let shadow_hash = sha256_hex(&format!("shadow-{worker}-{iteration}"));
        let chain_hash = compute_chain_hash(
            prev_hash,
            &decision,
            &policy_set,
            &policy_hash,
            &context,
            &input_hash,
            &shadow_hash,
            seq,
            &timestamp,
        );

        AuditEntry {
            schema: "aura-guard.audit.v1".into(),
            seq,
            audit_id: format!("{worker:04}-{iteration:02}"),
            request_id: None,
            timestamp,
            decision,
            policy_set,
            policy_hash,
            context,
            input_hash,
            shadow_hash,
            violations: vec![],
            prev_hash: prev_hash.to_string(),
            chain_hash,
        }
    }

    #[test]
    fn concurrent_appends_produce_one_contiguous_chain() {
        const WORKERS: usize = 256;
        const APPENDS_PER_WORKER: usize = 2;
        const TOTAL: usize = WORKERS * APPENDS_PER_WORKER;

        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("audit.jsonl");
        let writer = LogWriter::open(path.clone(), &genesis_hash()).expect("open writer");
        let barrier = Arc::new(Barrier::new(WORKERS));

        let handles: Vec<_> = (0..WORKERS)
            .map(|worker| {
                let writer = writer.clone();
                let barrier = barrier.clone();
                std::thread::spawn(move || {
                    barrier.wait();
                    let mut seqs = Vec::with_capacity(APPENDS_PER_WORKER);
                    for iteration in 0..APPENDS_PER_WORKER {
                        let entry = writer
                            .append_with(|seq, prev_hash| {
                                build_entry(seq, prev_hash, worker, iteration)
                            })
                            .expect("atomic append");
                        seqs.push(entry.seq);
                    }
                    seqs
                })
            })
            .collect();

        let mut seqs: Vec<u64> = handles
            .into_iter()
            .flat_map(|handle| handle.join().expect("worker completes"))
            .collect();
        seqs.sort_unstable();
        assert_eq!(seqs, (0..TOTAL as u64).collect::<Vec<_>>());

        let entries = read_all_entries(&path).expect("read written JSONL");
        assert_eq!(entries.len(), TOTAL);
        assert_eq!(
            verify_chain(&entries).expect("replay valid chain"),
            entries.last().unwrap().chain_hash
        );
        for (index, entry) in entries.iter().enumerate() {
            assert_eq!(entry.seq, index as u64);
            let expected_prev = if index == 0 {
                genesis_hash()
            } else {
                entries[index - 1].chain_hash.clone()
            };
            assert_eq!(entry.prev_hash, expected_prev);
        }
    }

    #[test]
    fn append_rejects_a_stale_prebuilt_entry_instead_of_forking_the_chain() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("audit.jsonl");
        let genesis = genesis_hash();
        let writer = LogWriter::open(path.clone(), &genesis).expect("open writer");

        let stale = build_entry(0, &genesis, 1, 0);
        writer
            .append_with(|seq, prev_hash| build_entry(seq, prev_hash, 2, 0))
            .expect("first entry committed");

        assert!(writer.append(&stale).is_err());
        let entries = read_all_entries(&path).expect("read JSONL");
        assert_eq!(entries.len(), 1);
        verify_chain(&entries).expect("chain remains intact");
    }
}
