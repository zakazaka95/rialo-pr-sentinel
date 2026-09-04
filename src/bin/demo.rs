use rialo_pr_sentinel::{HeadSha, SentinelState, Signals, Update};

fn main() {
    let head = HeadSha::from_hex("0123456789abcdef0123456789abcdef01234567").expect("demo SHA is valid");
    let signals = Signals {
        files_changed: 24,
        lines_changed: 840,
        touches_workflow: true,
        changes_dependencies: true,
        tests_missing: true,
        approvals: 1,
        ..Signals::default()
    };

    let mut state = SentinelState::default();
    if let Update::Changed(result) = state.update(head, signals) {
        println!("score={} reasons=0x{:04x} model={:016x} revision={}", result.score, result.reasons.bits(), result.model_hash, state.revision);
    }
}
