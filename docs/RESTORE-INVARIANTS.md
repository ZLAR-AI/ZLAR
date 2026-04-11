RESTORE INVARIANTS
Agent Health Subsystem (ZLAR 3.0)


RESTORE-INV-01  Absent trust state equals healthy

If no trust state file exists, the system behaves as if the agent is healthy.
No file means no degradation signal has been produced.
The gate does not penalize agents for the absence of assessment data.

Enforcement: lib/restore.sh _restore_read_trust_state()
Test: tests/test-restore.sh Section 2


RESTORE-INV-02  Malformed trust state equals degraded

If the trust state file exists but cannot be parsed, or contains an
unrecognized state value, the system treats the agent as degraded.
A file that should be valid JSON but is not is itself a signal that
something is wrong. The system does not ignore corruption.

Enforcement: lib/restore.sh _restore_read_trust_state(), trust-state.mjs loadTrustState()
Test: tests/test-restore.sh Section 3, test-trust-state.mjs


RESTORE-INV-03  Monotone state transitions

Trust state can only worsen: healthy to degraded to at_risk to suspended.
A transition that would improve the state (e.g. at_risk to degraded) is
rejected by the trust-state machine. The only path back to healthy is
an explicit human reset (RESTORE-INV-06).

This ensures that an adversarial agent cannot game its way back to a
trusted state by producing favorable-looking actions after triggering
detectors.

Enforcement: trust-state.mjs proposeTransition()
Test: test-trust-state.mjs (7 monotone transition tests)


RESTORE-INV-04  Restore cannot crash the gate

Every restore function called by the gate is error-trapped. If restore
fails for any reason (missing config, unreadable file, jq error, Node.js
unavailable), the gate continues with the original policy action unchanged.

The restore subsystem is advisory. It must never become a denial-of-service
vector against the gate it advises.

Enforcement: lib/restore.sh restore_check_escalation() (error trapping), gate source with 2>/dev/null || true
Test: tests/test-restore.sh Section 6


RESTORE-INV-05  Restore observes, it does not enforce

The restore subsystem produces trust state assessments. It does not
directly deny or allow actions. The gate remains the sole enforcement
point. Restore may escalate an action from allow to ask, bringing the
human into the loop. The human decides, not the detector.

This is the three-layer separation: action (agent), gate (policy), healer
(restore). No layer becomes absolute.

Enforcement: architectural (restore writes state files, gate reads them)


RESTORE-INV-06  Reset requires friction

Resetting trust state to healthy requires:
  - A reason (free text, must be non-empty)
  - A delay (configurable, default 30 seconds)
  - A signed history event recording the reset
  - A count (reset_count is incremented and recorded)

Daily reset limits are enforced (configurable, default 3 per day).
This prevents rubber-stamping of resets.

Enforcement: trust-state.mjs resetTrustState(), bin/zlar-restore reset
Test: test-trust-state.mjs (3 reset tests)


RESTORE-INV-07  Detectors are composable and independently removable

Each detector is a standalone module with a single evaluate() function.
Detectors can be added, removed, or replaced without modifying the engine.
A missing detector does not crash the engine or degrade other detectors.

Enforcement: restore-engine.mjs loadDetectors() (try-catch per detector)
Test: test-engine.mjs (detector loading tests)


RESTORE-INV-08  Trust state is derived from audit trail

The restore engine evaluates the signed audit trail. Trust state can be
rebuilt from the audit trail at any time by re-running the engine. The
trust state file is a cache of the most recent evaluation, not a source
of truth independent of the audit trail.

Enforcement: lib/restore-trigger.mjs (reads audit trail, runs engine)
