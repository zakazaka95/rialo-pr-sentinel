//! Deterministic scoring core for PR Sentinel.
//!
//! The crate deliberately performs no I/O. A host workflow normalizes GitHub data into
//! [`Signals`], calls [`score`], and persists [`SentinelState`] if [`Update::Changed`]
//! is returned.

use core::fmt;

#[cfg(feature = "rialo")]
pub mod rialo;

/// Maximum file count accepted by the scoring model before clamping.
pub const MAX_FILES_CHANGED: u32 = 10_000;
/// Maximum changed-line count accepted by the scoring model before clamping.
pub const MAX_LINES_CHANGED: u32 = 1_000_000;
/// Stable FNV-1a fingerprint of the model specification string.
pub const MODEL_HASH: u64 = fnv1a64(MODEL_SPEC.as_bytes());

const MODEL_SPEC: &str = "pr-sentinel/v1;files=ceil(min(n,10000)/10):max20;lines=ceil(min(n,1000000)/100):max20;binary=10;workflow=20;deps=15;permissions=25;sensitive=20;force_push=20;tests_failed=30;tests_missing=10;first_time=5;draft=-10;approvals=-5:max15;score=clamp0..100";

const fn fnv1a64(bytes: &[u8]) -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325_u64;
    let mut i = 0;
    while i < bytes.len() {
        hash ^= bytes[i] as u64;
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
        i += 1;
    }
    hash
}
/// Normalized, bounded inputs. Callers should set a flag if any matching item exists.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[allow(clippy::struct_excessive_bools)]
pub struct Signals {
    pub files_changed: u32,
    pub lines_changed: u32,
    pub has_binary: bool,
    pub touches_workflow: bool,
    pub changes_dependencies: bool,
    pub expands_permissions: bool,
    pub touches_sensitive_paths: bool,
    pub force_push_detected: bool,
    pub tests_failed: bool,
    pub tests_missing: bool,
    pub first_time_contributor: bool,
    pub draft: bool,
    pub approvals: u8,
}

/// Machine-readable reasons attached to a score.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ReasonBits(u16);

impl ReasonBits {
    pub const LARGE_FILE_SET: Self = Self(1 << 0);
    pub const LARGE_DIFF: Self = Self(1 << 1);
    pub const BINARY: Self = Self(1 << 2);
    pub const WORKFLOW: Self = Self(1 << 3);
    pub const DEPENDENCIES: Self = Self(1 << 4);
    pub const PERMISSIONS: Self = Self(1 << 5);
    pub const SENSITIVE_PATHS: Self = Self(1 << 6);
    pub const FORCE_PUSH: Self = Self(1 << 7);
    pub const TESTS_FAILED: Self = Self(1 << 8);
    pub const TESTS_MISSING: Self = Self(1 << 9);
    pub const FIRST_TIME_CONTRIBUTOR: Self = Self(1 << 10);
    pub const DRAFT: Self = Self(1 << 11);
    pub const APPROVED: Self = Self(1 << 12);

    #[must_use]
    pub const fn bits(self) -> u16 {
        self.0
    }

    #[must_use]
    pub const fn contains(self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }

    fn insert(&mut self, other: Self) {
        self.0 |= other.0;
    }
}

/// Reproducible result for one immutable PR head.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Assessment {
    pub score: u8,
    pub reasons: ReasonBits,
    pub model_hash: u64,
}

/// Score normalized signals using integer arithmetic only.
#[must_use]
pub fn score(signals: Signals) -> Assessment {
    let mut total = 0_i64;
    let mut reasons = ReasonBits::default();

    let files = signals.files_changed.min(MAX_FILES_CHANGED);
    if files != 0 {
        total += i64::from(files.div_ceil(10).min(20));
        if files > 50 {
            reasons.insert(ReasonBits::LARGE_FILE_SET);
        }
    }

    let lines = signals.lines_changed.min(MAX_LINES_CHANGED);
    if lines != 0 {
        total += i64::from(lines.div_ceil(100).min(20));
        if lines > 500 {
            reasons.insert(ReasonBits::LARGE_DIFF);
        }
    }

    add_flag(&mut total, &mut reasons, signals.has_binary, 10, ReasonBits::BINARY);
    add_flag(&mut total, &mut reasons, signals.touches_workflow, 20, ReasonBits::WORKFLOW);
    add_flag(&mut total, &mut reasons, signals.changes_dependencies, 15, ReasonBits::DEPENDENCIES);
    add_flag(&mut total, &mut reasons, signals.expands_permissions, 25, ReasonBits::PERMISSIONS);
    add_flag(&mut total, &mut reasons, signals.touches_sensitive_paths, 20, ReasonBits::SENSITIVE_PATHS);
    add_flag(&mut total, &mut reasons, signals.force_push_detected, 20, ReasonBits::FORCE_PUSH);
    add_flag(&mut total, &mut reasons, signals.tests_failed, 30, ReasonBits::TESTS_FAILED);
    add_flag(&mut total, &mut reasons, signals.tests_missing, 10, ReasonBits::TESTS_MISSING);
    add_flag(&mut total, &mut reasons, signals.first_time_contributor, 5, ReasonBits::FIRST_TIME_CONTRIBUTOR);

    if signals.draft {
        total -= 10;
        reasons.insert(ReasonBits::DRAFT);
    }
    if signals.approvals != 0 {
        total -= i64::from(signals.approvals.min(3)) * 5;
        reasons.insert(ReasonBits::APPROVED);
    }

    Assessment { score: u8::try_from(total.clamp(0, 100)).unwrap_or(100), reasons, model_hash: MODEL_HASH }
}

fn add_flag(total: &mut i64, reasons: &mut ReasonBits, enabled: bool, weight: i64, reason: ReasonBits) {
    if enabled {
        *total += weight;
        reasons.insert(reason);
    }
}

/// A parsed GitHub SHA-1 object identifier.
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct HeadSha([u8; 20]);

impl HeadSha {
    /// Parse exactly 40 ASCII hexadecimal characters.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidHeadSha`] unless `value` is exactly 40 hexadecimal characters.
    pub fn from_hex(value: &str) -> Result<Self, InvalidHeadSha> {
        if value.len() != 40 {
            return Err(InvalidHeadSha);
        }
        let mut bytes = [0_u8; 20];
        for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
            bytes[index] = (nibble(pair[0]).ok_or(InvalidHeadSha)? << 4) | nibble(pair[1]).ok_or(InvalidHeadSha)?;
        }
        Ok(Self(bytes))
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 20] {
        &self.0
    }
}

const fn nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

impl fmt::Debug for HeadSha {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InvalidHeadSha;

impl fmt::Display for InvalidHeadSha {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("head SHA must be exactly 40 hexadecimal characters")
    }
}

impl std::error::Error for InvalidHeadSha {}

/// Minimal state a reactive host needs to persist.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SentinelState {
    pub head_sha: Option<HeadSha>,
    pub assessment: Option<Assessment>,
    pub revision: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Update {
    Changed(Assessment),
    Unchanged(Assessment),
}

impl SentinelState {
    /// Re-score and mutate state only when `head_sha` changes.
    pub fn update(&mut self, head_sha: HeadSha, signals: Signals) -> Update {
        if self.head_sha == Some(head_sha) {
            if let Some(assessment) = self.assessment {
                return Update::Unchanged(assessment);
            }
        }

        let assessment = score(signals);
        self.head_sha = Some(head_sha);
        self.assessment = Some(assessment);
        self.revision = self.revision.saturating_add(1);
        Update::Changed(assessment)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SHA_A: &str = "0123456789abcdef0123456789abcdef01234567";
    const SHA_B: &str = "ffffffffffffffffffffffffffffffffffffffff";

    #[test]
    fn empty_input_is_zero_and_has_no_reasons() {
        let result = score(Signals::default());
        assert_eq!(result.score, 0);
        assert_eq!(result.reasons.bits(), 0);
        assert_eq!(result.model_hash, MODEL_HASH);
    }

    #[test]
    fn numeric_inputs_use_ceiling_buckets_thresholds_and_caps() {
        assert_eq!(score(Signals { files_changed: 1, ..Signals::default() }).score, 1);
        assert_eq!(score(Signals { files_changed: 50, ..Signals::default() }).score, 5);
        let large_files = score(Signals { files_changed: u32::MAX, ..Signals::default() });
        assert_eq!(large_files.score, 20);
        assert!(large_files.reasons.contains(ReasonBits::LARGE_FILE_SET));

        assert_eq!(score(Signals { lines_changed: 1, ..Signals::default() }).score, 1);
        assert_eq!(score(Signals { lines_changed: 500, ..Signals::default() }).score, 5);
        let large_diff = score(Signals { lines_changed: u32::MAX, ..Signals::default() });
        assert_eq!(large_diff.score, 20);
        assert!(large_diff.reasons.contains(ReasonBits::LARGE_DIFF));
    }

    #[test]
    fn every_boolean_reason_has_its_documented_weight_and_bit() {
        type FlagCase = (fn(&mut Signals), u8, ReasonBits);
        let cases: &[FlagCase] = &[
            (|s| s.has_binary = true, 10, ReasonBits::BINARY),
            (|s| s.touches_workflow = true, 20, ReasonBits::WORKFLOW),
            (|s| s.changes_dependencies = true, 15, ReasonBits::DEPENDENCIES),
            (|s| s.expands_permissions = true, 25, ReasonBits::PERMISSIONS),
            (|s| s.touches_sensitive_paths = true, 20, ReasonBits::SENSITIVE_PATHS),
            (|s| s.force_push_detected = true, 20, ReasonBits::FORCE_PUSH),
            (|s| s.tests_failed = true, 30, ReasonBits::TESTS_FAILED),
            (|s| s.tests_missing = true, 10, ReasonBits::TESTS_MISSING),
            (|s| s.first_time_contributor = true, 5, ReasonBits::FIRST_TIME_CONTRIBUTOR),
        ];
        for (set, weight, reason) in cases {
            let mut signals = Signals::default();
            set(&mut signals);
            let result = score(signals);
            assert_eq!(result.score, *weight);
            assert_eq!(result.reasons, *reason);
        }
    }

    #[test]
    fn mitigations_floor_at_zero_and_approval_credit_caps_at_three() {
        let mitigated = score(Signals { draft: true, approvals: u8::MAX, ..Signals::default() });
        assert_eq!(mitigated.score, 0);
        assert!(mitigated.reasons.contains(ReasonBits::DRAFT));
        assert!(mitigated.reasons.contains(ReasonBits::APPROVED));

        let base = Signals { has_binary: true, touches_workflow: true, ..Signals::default() };
        assert_eq!(score(Signals { approvals: 3, ..base }).score, 15);
        assert_eq!(score(Signals { approvals: 4, ..base }).score, 15);
    }

    #[test]
    fn aggregate_score_caps_at_one_hundred_and_is_deterministic() {
        let signals = Signals {
            files_changed: u32::MAX,
            lines_changed: u32::MAX,
            has_binary: true,
            touches_workflow: true,
            changes_dependencies: true,
            expands_permissions: true,
            touches_sensitive_paths: true,
            force_push_detected: true,
            tests_failed: true,
            tests_missing: true,
            first_time_contributor: true,
            draft: false,
            approvals: 0,
        };
        assert_eq!(score(signals).score, 100);
        assert_eq!(score(signals), score(signals));
        assert_ne!(MODEL_HASH, 0);
    }

    #[test]
    fn sha_parser_accepts_case_and_rejects_wrong_shape() {
        assert_eq!(HeadSha::from_hex(SHA_A).unwrap().as_bytes()[0], 0x01);
        assert_eq!(HeadSha::from_hex(&SHA_A.to_uppercase()).unwrap(), HeadSha::from_hex(SHA_A).unwrap());
        assert!(HeadSha::from_hex("abc").is_err());
        assert!(HeadSha::from_hex("z123456789abcdef0123456789abcdef01234567").is_err());
        assert_eq!(format!("{:?}", HeadSha::from_hex(SHA_A).unwrap()), SHA_A);
    }

    #[test]
    fn state_changes_only_for_a_new_head_sha() {
        let mut state = SentinelState::default();
        let a = HeadSha::from_hex(SHA_A).unwrap();
        let b = HeadSha::from_hex(SHA_B).unwrap();
        let low = Signals { has_binary: true, ..Signals::default() };
        let high = Signals { tests_failed: true, ..Signals::default() };

        let first = state.update(a, low);
        assert_eq!(first, Update::Changed(score(low)));
        let snapshot = state;
        assert_eq!(state.update(a, high), Update::Unchanged(score(low)));
        assert_eq!(state, snapshot, "signals for an old head must be ignored");
        assert_eq!(state.update(b, high), Update::Changed(score(high)));
        assert_eq!(state.revision, 2);
    }

    #[test]
    fn revision_saturates_instead_of_wrapping() {
        let mut state = SentinelState { revision: u64::MAX, ..SentinelState::default() };
        state.update(HeadSha::from_hex(SHA_A).unwrap(), Signals::default());
        assert_eq!(state.revision, u64::MAX);
    }
}
