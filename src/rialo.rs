//! Rialo Venus storage adapter.
//!
//! This module is feature-gated so the deterministic scoring core keeps its
//! dependency-free default build. A Venus program can pass its payer, dedicated
//! PR-Sentinel workflow PDA, and system-program accounts to
//! [`evaluate_and_persist`].

use rialo_venus::{
    derive_workflow_address, read_from_storage,
    reexports::{
        rialo_s_program::{account_info::AccountInfo, program_error::ProgramError, pubkey::Pubkey, system_program},
        rialo_types::Nonce,
    },
    write_to_storage,
};
use serde::{Deserialize, Serialize};

use crate::{Assessment, HeadSha, ReasonBits, SentinelState, Signals, Update, MODEL_HASH};

/// Version of the bincode payload stored in the dedicated Venus workflow PDA.
pub const STORAGE_FORMAT_VERSION: u8 = 1;

const STORAGE_MAGIC: [u8; 8] = *b"PRSENTNL";
const VALID_REASON_BITS: u16 = (1 << 13) - 1;
const STORED_STATE_LEN: usize = 48;

/// Result returned to the Venus workflow after evaluating a PR head.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WorkflowOutcome {
    pub update: Update,
    pub revision: u64,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
struct StoredState {
    magic: [u8; 8],
    format_version: u8,
    head_sha: [u8; 20],
    score: u8,
    reason_bits: u16,
    model_hash: u64,
    revision: u64,
}

impl StoredState {
    fn into_core(self) -> Result<SentinelState, ProgramError> {
        if self.magic != STORAGE_MAGIC
            || self.format_version != STORAGE_FORMAT_VERSION
            || self.score > 100
            || self.reason_bits & !VALID_REASON_BITS != 0
            || self.model_hash != MODEL_HASH
        {
            return Err(ProgramError::InvalidAccountData);
        }

        Ok(SentinelState {
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
            magic: STORAGE_MAGIC,
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
/// This adapter owns the complete payload of a dedicated PR-Sentinel workflow PDA. It
/// must not share a slug/PDA with generated Venus DSL workflow state. Accounts are
/// validated before any read or unchanged return. Existing bytes are decoded with
/// Venus' official `read_from_storage` helper; malformed, foreign, or differently
/// versioned state fails closed. `write_to_storage` is called only when
/// [`SentinelState::update`] returns [`Update::Changed`].
///
/// # Errors
///
/// Returns [`ProgramError`] for invalid account identity, permissions, ownership, or
/// stored state, and for any Venus storage failure.
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
    let workflow_pda_slug: Nonce = workflow_pda_slug.into();
    validate_accounts(program_id, workflow_pda_slug, payer_account, workflow_account, system_program_account)?;

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
    decode_state(&data).map(Some)
}

fn decode_state(data: &[u8]) -> Result<SentinelState, ProgramError> {
    if data.len() != STORED_STATE_LEN {
        return Err(ProgramError::InvalidAccountData);
    }
    read_from_storage::<StoredState>(data)?.into_core()
}

fn validate_accounts(
    program_id: &Pubkey,
    workflow_pda_slug: Nonce,
    payer_account: &AccountInfo<'_>,
    workflow_account: &AccountInfo<'_>,
    system_program_account: &AccountInfo<'_>,
) -> Result<(), ProgramError> {
    if !system_program::check_id(system_program_account.key) {
        return Err(ProgramError::IncorrectProgramId);
    }
    if !payer_account.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }
    if !payer_account.is_writable || !workflow_account.is_writable {
        return Err(ProgramError::InvalidArgument);
    }

    let (expected_workflow, _) = derive_workflow_address(program_id, payer_account.key, workflow_pda_slug);
    if expected_workflow != *workflow_account.key {
        return Err(ProgramError::InvalidAccountData);
    }

    if workflow_account.kelvins() == 0 {
        if workflow_account.data_len() != 0 {
            return Err(ProgramError::InvalidAccountData);
        }
    } else if workflow_account.owner != program_id {
        return Err(ProgramError::InvalidAccountOwner);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::score;

    const SHA_A: &str = "0123456789abcdef0123456789abcdef01234567";

    #[test]
    fn stored_state_round_trips_to_the_core_model() {
        let head = HeadSha::from_hex(SHA_A).unwrap();
        let assessment = score(Signals { touches_workflow: true, ..Signals::default() });
        let state = SentinelState { head_sha: Some(head), assessment: Some(assessment), revision: 7 };

        assert_eq!(StoredState::from(state).into_core(), Ok(state));
    }

    #[test]
    fn old_storage_versions_fail_closed() {
        let stored = StoredState {
            magic: STORAGE_MAGIC,
            format_version: STORAGE_FORMAT_VERSION + 1,
            head_sha: [0; 20],
            score: 99,
            reason_bits: VALID_REASON_BITS,
            model_hash: MODEL_HASH,
            revision: 10,
        };

        assert_eq!(stored.into_core(), Err(ProgramError::InvalidAccountData));
    }

    #[test]
    fn foreign_or_corrupt_storage_fails_closed() {
        let state = SentinelState { head_sha: Some(HeadSha::from_hex(SHA_A).unwrap()), assessment: Some(score(Signals::default())), revision: 1 };

        let mut foreign = StoredState::from(state);
        foreign.magic = *b"FOREIGN!";
        assert_eq!(foreign.into_core(), Err(ProgramError::InvalidAccountData));

        let mut invalid_score = StoredState::from(state);
        invalid_score.score = 101;
        assert_eq!(invalid_score.into_core(), Err(ProgramError::InvalidAccountData));

        let mut invalid_reasons = StoredState::from(state);
        invalid_reasons.reason_bits = 1 << 15;
        assert_eq!(invalid_reasons.into_core(), Err(ProgramError::InvalidAccountData));

        let mut obsolete_model = StoredState::from(state);
        obsolete_model.model_hash ^= 1;
        assert_eq!(obsolete_model.into_core(), Err(ProgramError::InvalidAccountData));
    }

    #[test]
    fn trailing_storage_bytes_fail_closed() {
        let state = SentinelState { head_sha: Some(HeadSha::from_hex(SHA_A).unwrap()), assessment: Some(score(Signals::default())), revision: 1 };
        let mut encoded = rialo_venus::reexports::bincode::serialize(&StoredState::from(state)).expect("stored state serializes");
        assert_eq!(encoded.len(), STORED_STATE_LEN);
        encoded.push(0);

        assert_eq!(decode_state(&encoded), Err(ProgramError::InvalidAccountData));
    }

    #[test]
    fn account_validation_applies_before_unchanged_paths() {
        let program_id = Pubkey::new_unique();
        let payer_key = Pubkey::new_unique();
        let slug = Nonce::from("pr-sentinel-tests");
        let (workflow_key, _) = derive_workflow_address(&program_id, &payer_key, slug);

        let mut payer_kelvins = 1;
        let mut payer_data = [];
        let payer = AccountInfo::new(&payer_key, false, true, &mut payer_kelvins, &mut payer_data, &system_program::ID, false, 0);
        let mut workflow_kelvins = 1;
        let mut workflow_data = [0_u8; 1];
        let workflow = AccountInfo::new(&workflow_key, false, true, &mut workflow_kelvins, &mut workflow_data, &program_id, false, 0);
        let mut system_kelvins = 0;
        let mut system_data = [];
        let system = AccountInfo::new(&system_program::ID, false, false, &mut system_kelvins, &mut system_data, &system_program::ID, true, 0);

        assert_eq!(validate_accounts(&program_id, slug, &payer, &workflow, &system), Err(ProgramError::MissingRequiredSignature));
    }

    #[test]
    fn account_validation_rejects_wrong_pda_and_owner() {
        let program_id = Pubkey::new_unique();
        let payer_key = Pubkey::new_unique();
        let slug = Nonce::from("pr-sentinel-tests");
        let (workflow_key, _) = derive_workflow_address(&program_id, &payer_key, slug);
        let wrong_workflow_key = Pubkey::new_unique();

        let mut payer_kelvins = 1;
        let mut payer_data = [];
        let payer = AccountInfo::new(&payer_key, true, true, &mut payer_kelvins, &mut payer_data, &system_program::ID, false, 0);
        let mut wrong_key_kelvins = 1;
        let mut wrong_key_data = [0_u8; 1];
        let wrong_key = AccountInfo::new(&wrong_workflow_key, false, true, &mut wrong_key_kelvins, &mut wrong_key_data, &program_id, false, 0);
        let foreign_owner = Pubkey::new_unique();
        let mut wrong_owner_kelvins = 1;
        let mut wrong_owner_data = [0_u8; 1];
        let wrong_owner = AccountInfo::new(&workflow_key, false, true, &mut wrong_owner_kelvins, &mut wrong_owner_data, &foreign_owner, false, 0);
        let mut system_kelvins = 0;
        let mut system_data = [];
        let system = AccountInfo::new(&system_program::ID, false, false, &mut system_kelvins, &mut system_data, &system_program::ID, true, 0);

        assert_eq!(validate_accounts(&program_id, slug, &payer, &wrong_key, &system), Err(ProgramError::InvalidAccountData));
        assert_eq!(validate_accounts(&program_id, slug, &payer, &wrong_owner, &system), Err(ProgramError::InvalidAccountOwner));
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
