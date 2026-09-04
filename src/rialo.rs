//! Rialo Venus storage adapter.
//!
//! This module is feature-gated so the deterministic scoring core keeps its
//! dependency-free default build. A Venus program can pass its payer, workflow
//! PDA, and system-program accounts to [`evaluate_and_persist`].

use rialo_venus::{
    read_from_storage,
    reexports::{
        rialo_s_program::{account_info::AccountInfo, program_error::ProgramError, pubkey::Pubkey},
        rialo_types::Nonce,
    },
    write_to_storage,
};
use serde::{Deserialize, Serialize};

use crate::{Assessment, HeadSha, ReasonBits, SentinelState, Signals, Update};

/// Version of the bincode payload stored in the Venus workflow PDA.
pub const STORAGE_FORMAT_VERSION: u8 = 1;

/// Result returned to the Venus workflow after evaluating a PR head.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WorkflowOutcome {
    pub update: Update,
    pub revision: u64,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
struct StoredState {
    format_version: u8,
    head_sha: [u8; 20],
    score: u8,
    reason_bits: u16,
    model_hash: u64,
    revision: u64,
}

impl StoredState {
    const fn into_core(self) -> Option<SentinelState> {
        if self.format_version != STORAGE_FORMAT_VERSION {
            return None;
        }

        Some(SentinelState {
            head_sha: Some(HeadSha(self.head_sha)),
            assessment: Some(Assessment { score: self.score, reasons: ReasonBits(self.reason_bits), model_hash: self.model_hash }),
            revision: self.revision,
        })
    }
}

impl From<SentinelState> for StoredState {
    fn from(state: SentinelState) -> Self {
        let head_sha = state.head_sha.expect("changed state has a head SHA");
        let assessment = state.assessment.expect("changed state has an assessment");
        Self {
            format_version: STORAGE_FORMAT_VERSION,
            head_sha: *head_sha.as_bytes(),
            score: assessment.score,
            reason_bits: assessment.reasons.bits(),
            model_hash: assessment.model_hash,
            revision: state.revision,
        }
    }
}

/// Score a normalized PR snapshot and persist it through Venus only for a new head SHA.
///
/// Existing bytes are decoded with Venus' official `read_from_storage` helper. Missing,
/// invalid, or differently-versioned state is treated as uninitialized, matching the
/// generated Venus workflow preflight behavior. `write_to_storage` is called only when
/// [`SentinelState::update`] returns [`Update::Changed`].
///
/// # Errors
///
/// Returns the [`ProgramError`] produced by Venus when account data cannot be borrowed
/// or the changed assessment cannot be stored.
pub fn evaluate_and_persist<'account_info, NONCE>(
    program_id: &Pubkey,
    workflow_pda_slug: NONCE,
    payer_account: &AccountInfo<'account_info>,
    workflow_account: &AccountInfo<'account_info>,
    system_program_account: &AccountInfo<'account_info>,
    head_sha: HeadSha,
    signals: Signals,
) -> Result<WorkflowOutcome, ProgramError>
where
    NONCE: Into<Nonce>,
{
    let mut state = load_state(workflow_account)?.unwrap_or_default();
    let update = state.update(head_sha, signals);

    if matches!(update, Update::Changed(_)) {
        write_to_storage(program_id, workflow_pda_slug, payer_account, workflow_account, system_program_account, &StoredState::from(state))?;
    }

    Ok(WorkflowOutcome { update, revision: state.revision })
}

fn load_state(workflow_account: &AccountInfo<'_>) -> Result<Option<SentinelState>, ProgramError> {
    if workflow_account.kelvins() == 0 || workflow_account.data_len() == 0 {
        return Ok(None);
    }

    let data = workflow_account.try_borrow_data()?;
    Ok(read_from_storage::<StoredState>(&data).ok().and_then(StoredState::into_core))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{score, MODEL_HASH};

    const SHA_A: &str = "0123456789abcdef0123456789abcdef01234567";

    #[test]
    fn stored_state_round_trips_to_the_core_model() {
        let head = HeadSha::from_hex(SHA_A).unwrap();
        let assessment = score(Signals { touches_workflow: true, ..Signals::default() });
        let state = SentinelState { head_sha: Some(head), assessment: Some(assessment), revision: 7 };

        assert_eq!(StoredState::from(state).into_core(), Some(state));
    }

    #[test]
    fn old_storage_versions_are_not_loaded() {
        let stored = StoredState {
            format_version: STORAGE_FORMAT_VERSION + 1,
            head_sha: [0; 20],
            score: 99,
            reason_bits: u16::MAX,
            model_hash: MODEL_HASH,
            revision: 10,
        };

        assert_eq!(stored.into_core(), None);
    }

    #[test]
    fn restored_state_preserves_unchanged_head_semantics() {
        let head = HeadSha::from_hex(SHA_A).unwrap();
        let original = Signals { has_binary: true, ..Signals::default() };
        let mut state = SentinelState::default();
        assert_eq!(state.update(head, original), Update::Changed(score(original)));

        let mut restored = StoredState::from(state).into_core().unwrap();
        let replacement = Signals { tests_failed: true, ..Signals::default() };
        assert_eq!(restored.update(head, replacement), Update::Unchanged(score(original)));
        assert_eq!(restored.revision, 1);
    }
}
