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


RESTORE-INV-09  Trust state integrity

The trust state file and evaluation history file are HMAC-signed when a key
is available (etc/keys/restore-hmac.key). The gate verifies the HMAC on read.
A file with a missing or mismatched HMAC is treated as tampered:
  - Trust state: treated as degraded (consistent with INV-02)
  - Evaluation history: treated as empty (conservative; slowing-down detector
    does not fire, which means no sensitivity increase)

Without an HMAC key, integrity checking is skipped. The system works but
without tamper protection. HMAC is opt-in, recommended.

Enforcement: trust-state.mjs loadTrustState/saveTrustState (HMAC sign/verify),
  evaluation-history.mjs loadHistory/appendHistory (HMAC sign/verify),
  lib/restore.sh _restore_read_trust_state_from_file (shell-side verification)
Test: test-hardening.mjs (5 HMAC tests)


RESTORE-INV-10  Thresholds resist evasion

Detector-to-state thresholds are jittered by +/-10% on each evaluation. An
agent that knows the nominal thresholds cannot reliably stay just below them
because the actual thresholds shift unpredictably.

This is non-deterministic only in the observation layer. Policy enforcement
in the gate remains fully deterministic.

Enforcement: restore-engine.mjs evaluate() (jitter before threshold comparison)


RESTORE-INV-11  Evaluation reads are bounded

The restore trigger and CLI read the audit trail in bounded 64KB reverse-read
chunks with a hard cap of 500 events per evaluation. This prevents memory
exhaustion on long-running systems and defends against audit trail flooding
as a denial-of-service vector.

Enforcement: lib/restore-trigger.mjs readSessionTrace(), bin/zlar-restore cmd_evaluate()


RESTORE-INV-12  Config integrity (fail-closed)

The restore config (etc/restore-config.json) controls whether Agent Health
is enabled and what escalation levels apply. An agent that tampers with
this config to set enabled=false disables the entire subsystem.

When a config HMAC key exists (etc/keys/restore-config-hmac.key), the gate
verifies the config against its HMAC sidecar (restore-config.json.hmac) on
every init. Verification failure forces restore to fail CLOSED:
  - enabled is forced to true
  - all escalation levels are forced to deny
  - Telegram alert is sent
  - gate log records the failure

The attacker who tampers with config to disable restore gets the opposite
of what they wanted: maximum escalation on every action.

Without a config HMAC key, integrity checking is skipped. The system works
but R012 (path-based deny) is the only defense. Config HMAC is recommended.

Enforcement: lib/restore.sh _restore_verify_config_integrity(), _restore_force_closed()
  config-integrity.mjs signConfig/verifyConfig, bin/zlar-restore sign-config
Test: test-hardening.mjs (4 config integrity tests)


RESTORE-INV-13  Multi-detector convergence for escalation

A single high-scoring detector can only push trust state to degraded.
Reaching at_risk or suspended requires 2 or more detectors with weighted
signals above the convergence floor (the degraded threshold).

This prevents a single miscalibrated or false-positive detector from
cascading into full escalation. Degraded is visible (Telegram notification)
but does not change action routing. at_risk and suspended change action
routing and therefore require convergent evidence from multiple independent
behavioral signals.

The convergence floor equals the degraded threshold. Any detector whose
weighted signal (score times confidence) exceeds this floor counts as
active. The active_detectors count is included in the evaluation result
for transparency.

Origin: v3.0.4. Production false positive where action_silence alone at
score 1.0 pushed trust state directly to at_risk, escalating all policy
allows to asks and interrupting the human 5 times in 30 seconds.

Enforcement: restore-engine.mjs evaluate() (activeDetectorCount filter)
Test: test-engine.mjs (3 convergence rule tests)
