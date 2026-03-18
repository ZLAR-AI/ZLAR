# ZLAR-OC: Audit Event Schema & Policy Rule Format

**Date:** March 4, 2026
**Depends on:** All prior design documents + OpenClaw observability recon
**Purpose:** Define the shared vocabulary between observation and enforcement — the event
schema that both layers speak, and the policy format the gate mechanically enforces

---

## Design Principles

1. **One schema, two producers** — ZLAR (Claude Code hooks) and ZLAR-OC (OS sandbox) both
   write events in the same format to the same audit trail
2. **The gate reads policy, not events** — the gate enforces signed rules. The observation
   pipeline reads events and proposes policy changes. They never cross.
3. **Append-only audit trail** — events are never modified or deleted. The trail is the
   ground truth for all policy evolution.
4. **Events are facts, not opinions** — an event records what happened, not whether it was
   good or bad. Classification lives in the policy layer above.

---

## Part 1: Audit Event Schema

### Event Envelope

Every event in the ZLAR/ZLAR-OC audit trail is a single JSON line in a `.jsonl` file:

```typescript
type AuditEvent = {
  // ─── Identity ───────────────────────────────────────────
  id: string;                    // UUIDv7 (time-ordered)
  ts: string;                    // ISO 8601 with timezone
  seq: number;                   // Monotonic per-source sequence number

  // ─── Source ─────────────────────────────────────────────
  source: AuditSource;           // Which enforcement layer produced this
  host: string;                  // Machine hostname
  user: string;                  // OS user that triggered the event

  // ─── Classification ─────────────────────────────────────
  domain: AuditDomain;           // Event category
  action: string;                // What happened (domain-specific)
  outcome: "allow" | "deny" | "ask" | "timeout" | "error";

  // ─── Context ────────────────────────────────────────────
  session?: string;              // OpenClaw session key or Claude Code session
  agent?: string;                // Agent ID (for sub-agents)
  tool?: string;                 // Tool name if applicable
  channel?: string;              // Message channel (whatsapp, telegram, slack, cli)

  // ─── Payload ────────────────────────────────────────────
  detail: Record<string, unknown>; // Domain-specific data (see below)

  // ─── Policy Match ───────────────────────────────────────
  rule?: string;                 // Policy rule ID that matched (if any)
  policy_version?: string;       // Policy version in effect
};
```

### Source Types

```typescript
type AuditSource =
  | "zlar"           // ZLAR Layer 1 — Claude Code hooks
  | "sandbox"        // ZLAR-OC Layer 2b — sandbox-exec denials
  | "pf"             // ZLAR-OC Layer 3 — pf firewall
  | "gate"           // ZLAR-OC gate — policy enforcement decisions
  | "observer"       // ZLAR-OC observation pipeline — derived events
  | "openclaw"       // OpenClaw's own logs (passthrough)
  ;
```

### Domains

```typescript
type AuditDomain =
  // ─── Execution ──────────────────────────────────────────
  | "exec"           // Shell command execution
  | "process"        // Process spawn/fork/kill
  | "binary"         // Binary execution attempt

  // ─── File System ────────────────────────────────────────
  | "fs"             // File read/write/delete/move
  | "fs.config"      // Config file modification

  // ─── Network ────────────────────────────────────────────
  | "net.outbound"   // Outbound connection attempt
  | "net.inbound"    // Inbound connection received
  | "net.dns"        // DNS resolution
  | "net.http"       // HTTP request/response

  // ─── Browser ────────────────────────────────────────────
  | "browser"        // Browser automation action
  | "browser.nav"    // Page navigation
  | "browser.eval"   // JavaScript evaluation

  // ─── Session ────────────────────────────────────────────
  | "session"        // Session lifecycle
  | "agent"          // Agent lifecycle
  | "subagent"       // Sub-agent spawn/end

  // ─── Message ────────────────────────────────────────────
  | "message.in"     // Inbound message
  | "message.out"    // Outbound message

  // ─── System ─────────────────────────────────────────────
  | "system"         // System-level events (keychain, osascript, etc.)
  | "policy"         // Policy changes
  ;
```

### Domain-Specific Detail Schemas

#### `exec` — Shell Command Execution

```typescript
type ExecDetail = {
  command: string;              // Full command text
  argv: string[];               // Parsed argv
  binary: string;               // Resolved binary path
  cwd?: string;                 // Working directory
  exit_code?: number;           // Exit code (if completed)
  timed_out?: boolean;
  duration_ms?: number;
  stdout_preview?: string;      // First 256 chars
  stderr_preview?: string;      // First 256 chars
  approval?: "auto" | "allowlist" | "ask" | "denied";
};
```

#### `net.outbound` — Network Connection

```typescript
type NetOutboundDetail = {
  proto: "tcp" | "udp";
  dst_ip: string;
  dst_port: number;
  dst_host?: string;            // DNS name if resolved
  src_port?: number;
  blocked_by?: "pf" | "sandbox" | "ssrf_guard";
  table_match?: string;         // pf table that matched (e.g. "blocked_nets")
};
```

#### `browser.nav` — Browser Navigation

```typescript
type BrowserNavDetail = {
  url: string;
  profile?: string;
  tab_id?: string;
  blocked_by?: "navigation_guard" | "ssrf_guard" | "sandbox";
};
```

#### `fs` — File System Access

```typescript
type FsDetail = {
  path: string;
  operation: "read" | "write" | "delete" | "move" | "mkdir" | "stat";
  blocked_by?: "sandbox" | "permissions";
  target_path?: string;         // For move/rename
};
```

#### `session` / `agent` — Lifecycle

```typescript
type SessionDetail = {
  session_id?: string;
  session_key?: string;
  event: "start" | "end" | "error" | "compaction";
  duration_ms?: number;
  error?: string;
};

type AgentDetail = {
  agent_id: string;
  parent_agent?: string;
  spawn_depth?: number;
  event: "spawn" | "end" | "error";
  tools_available?: string[];
};
```

#### `policy` — Policy Change Events

```typescript
type PolicyDetail = {
  event: "loaded" | "updated" | "signed" | "expired" | "rejected";
  version: string;
  previous_version?: string;
  signer?: string;              // Who signed the policy
  rule_count?: number;
  hash: string;                 // SHA-256 of policy file
};
```

---

## Part 2: Event Sources & Collection

### Source Map

```
┌─────────────────────────────────────────────────────────────────┐
│                                                                 │
│   ┌──────────────┐  syslog/asl   ┌──────────────────────────┐ │
│   │  sandbox-exec │──────────────▶│                          │ │
│   │  (denials)    │               │                          │ │
│   └──────────────┘               │   ZLAR-OC Observer       │ │
│                                   │   (runs as admin)        │ │
│   ┌──────────────┐  pflog0       │                          │ │
│   │  pf firewall  │──────────────▶│   Reads all sources,    │ │
│   │  (drops)      │               │   normalizes to schema, │ │
│   └──────────────┘               │   writes to audit trail  │ │
│                                   │                          │ │
│   ┌──────────────┐  file tail    │                          │ │
│   │  OpenClaw     │──────────────▶│                          │ │
│   │  stdout/err   │               │                          │ │
│   └──────────────┘               └──────────┬───────────────┘ │
│                                              │                 │
│   ┌──────────────┐  file tail               │                 │
│   │  OpenClaw     │──────────────▶           │                 │
│   │  log file     │                          │                 │
│   │  (JSON lines) │                          ▼                 │
│   └──────────────┘               ┌──────────────────────────┐ │
│                                   │  /var/log/zlar-oc/       │ │
│   ┌──────────────┐  direct       │  audit.jsonl             │ │
│   │  ZLAR hooks   │──────────────▶│  (append-only)           │ │
│   │  (Claude Code)│               └──────────────────────────┘ │
│   └──────────────┘                                             │
└─────────────────────────────────────────────────────────────────┘
```

### Collection Methods by Source

| Source | How Collected | Runs As | Latency |
|---|---|---|---|
| sandbox-exec denials | `log stream --predicate 'process == "sandboxd"'` | admin | ~1s |
| pf firewall drops | `tcpdump -i pflog0` (parsed) | root | ~100ms |
| OpenClaw stdout/stderr | `tail -f /var/log/zlar-oc/openclaw-*.log` | admin | ~100ms |
| OpenClaw JSON log | `tail -f /tmp/.openclaw/openclaw-*.log` (JSON lines) | admin | ~100ms |
| OpenClaw transcripts | `fswatch ~/.openclaw/agents/` (inotify-equivalent) | admin | ~1s |
| ZLAR hooks (Claude Code) | Direct write from ZLAR's audit module | admin | ~10ms |

### Why NOT Use OpenClaw's Plugin SDK

The handoff document states the invariant: *"The enforcement layer — built separately, owned by
a different user, invisible to the agent — constrains it."*

An OpenClaw plugin runs **inside** the agent process. It would:
- Be visible to the agent (it could detect and potentially manipulate the plugin)
- Run as `aiagent` (compromised if the agent is compromised)
- Be unable to observe sandbox-exec and pf events (OS-level, not process-level)
- Create a circular dependency (the thing being watched runs the watcher)

ZLAR-OC's observer runs as `admin`, outside the sandbox, reading the agent's exhaust.
The agent doesn't know it's being watched. This is by design.

---

## Part 3: Policy Rule Format

### Policy File Structure

A policy is a signed JSON file containing ordered rules. The gate evaluates rules top-to-bottom
and takes the action of the first match.

File: `/usr/local/etc/zlar-oc/policies/active.policy.json`

```typescript
type Policy = {
  // ─── Metadata ───────────────────────────────────────────
  version: string;              // Semver (e.g. "1.0.0")
  created_at: string;           // ISO 8601
  expires_at?: string;          // Optional expiration
  author: string;               // Who created this policy
  description: string;          // Human-readable purpose

  // ─── Signature ──────────────────────────────────────────
  signature: {
    algorithm: "ed25519";       // Signing algorithm
    public_key: string;         // Base64-encoded public key
    value: string;              // Base64-encoded signature over canonical JSON
  };

  // ─── Default Action ─────────────────────────────────────
  default_action: "deny" | "allow" | "ask";

  // ─── Rules (evaluated top-to-bottom, first match wins) ──
  rules: PolicyRule[];
};
```

### Policy Rules

```typescript
type PolicyRule = {
  id: string;                   // Unique rule identifier (e.g. "R001")
  description: string;          // Human-readable explanation
  enabled: boolean;             // Can be disabled without removal

  // ─── Match Conditions (ALL must match) ──────────────────
  match: {
    domain?: AuditDomain | AuditDomain[];    // Event domain(s)
    action?: string | string[];              // Action pattern(s)
    source?: AuditSource | AuditSource[];    // Source filter

    // Pattern matching on detail fields
    detail?: {
      [field: string]: PolicyMatcher;
    };

    // Context filters
    session?: string | string[];
    agent?: string | string[];
    tool?: string | string[];
    channel?: string | string[];
  };

  // ─── Action ─────────────────────────────────────────────
  action: "allow" | "deny" | "ask" | "log";

  // ─── Ask Configuration (only if action == "ask") ────────
  ask?: {
    channel: "telegram" | "slack" | "cli";   // Where to send approval request
    timeout_s: number;                       // Seconds to wait for response
    timeout_action: "deny" | "allow";        // What to do on timeout
    message_template?: string;               // Custom approval message
  };

  // ─── Audit ──────────────────────────────────────────────
  audit: boolean;               // Whether to log this match to audit trail
  severity?: "info" | "warn" | "critical";
};
```

### Pattern Matchers

```typescript
type PolicyMatcher =
  | { eq: string | number | boolean }        // Exact match
  | { ne: string | number | boolean }        // Not equal
  | { in: (string | number)[] }              // In set
  | { not_in: (string | number)[] }          // Not in set
  | { glob: string }                         // Glob pattern (e.g. "*.sh")
  | { regex: string }                        // Regular expression
  | { prefix: string }                       // String prefix
  | { contains: string }                     // String contains
  | { exists: boolean }                      // Field exists/not exists
  | { gt: number }                           // Greater than
  | { lt: number }                           // Less than
  ;
```

---

## Part 4: Example Policy

```json
{
  "version": "1.0.0",
  "created_at": "2026-04-15T10:00:00Z",
  "author": "admin",
  "description": "ZLAR-OC initial conservative policy for OpenClaw M5 Max deployment",

  "signature": {
    "algorithm": "ed25519",
    "public_key": "base64...",
    "value": "base64..."
  },

  "default_action": "ask",

  "rules": [
    {
      "id": "R001",
      "description": "Allow read-only system info commands",
      "enabled": true,
      "match": {
        "domain": "exec",
        "detail": {
          "binary": { "in": ["/usr/bin/uname", "/bin/hostname", "/usr/bin/whoami", "/usr/bin/env"] }
        }
      },
      "action": "allow",
      "audit": true,
      "severity": "info"
    },
    {
      "id": "R002",
      "description": "Allow git operations in workspace",
      "enabled": true,
      "match": {
        "domain": "exec",
        "detail": {
          "binary": { "eq": "/usr/bin/git" },
          "cwd": { "prefix": "/Users/aiagent/workspace" }
        }
      },
      "action": "allow",
      "audit": true,
      "severity": "info"
    },
    {
      "id": "R003",
      "description": "Allow ffmpeg/ffprobe for media processing",
      "enabled": true,
      "match": {
        "domain": "exec",
        "detail": {
          "binary": { "in": ["/opt/homebrew/bin/ffmpeg", "/opt/homebrew/bin/ffprobe"] }
        }
      },
      "action": "allow",
      "audit": true,
      "severity": "info"
    },
    {
      "id": "R010",
      "description": "Ask for any shell command not matched above",
      "enabled": true,
      "match": {
        "domain": "exec"
      },
      "action": "ask",
      "ask": {
        "channel": "telegram",
        "timeout_s": 120,
        "timeout_action": "deny",
        "message_template": "OpenClaw wants to run: {{detail.command}}\nSession: {{session}}\nAgent: {{agent}}"
      },
      "audit": true,
      "severity": "warn"
    },
    {
      "id": "R020",
      "description": "Deny all LAN access (redundant with pf, defense in depth)",
      "enabled": true,
      "match": {
        "domain": "net.outbound",
        "detail": {
          "dst_ip": { "regex": "^(10\\.|172\\.(1[6-9]|2[0-9]|3[01])\\.|192\\.168\\.)" }
        }
      },
      "action": "deny",
      "audit": true,
      "severity": "critical"
    },
    {
      "id": "R021",
      "description": "Allow HTTPS to known API endpoints",
      "enabled": true,
      "match": {
        "domain": "net.outbound",
        "detail": {
          "dst_host": { "in": [
            "api.anthropic.com",
            "api.openai.com",
            "huggingface.co",
            "cdn-lfs.huggingface.co"
          ]},
          "dst_port": { "eq": 443 }
        }
      },
      "action": "allow",
      "audit": true,
      "severity": "info"
    },
    {
      "id": "R030",
      "description": "Deny file access outside agent home",
      "enabled": true,
      "match": {
        "domain": "fs",
        "detail": {
          "path": { "not_in": ["/Users/aiagent/", "/tmp/openclaw-", "/var/folders/"] }
        }
      },
      "action": "deny",
      "audit": true,
      "severity": "critical"
    },
    {
      "id": "R040",
      "description": "Log all browser navigations",
      "enabled": true,
      "match": {
        "domain": "browser.nav"
      },
      "action": "allow",
      "audit": true,
      "severity": "info"
    },
    {
      "id": "R050",
      "description": "Log all sub-agent spawns",
      "enabled": true,
      "match": {
        "domain": "subagent"
      },
      "action": "allow",
      "audit": true,
      "severity": "warn"
    }
  ]
}
```

---

## Part 5: Policy Signing

### Why Sign Policies

The gate is dumb and reliable. It loads whatever signed policy it's given and enforces it
mechanically. Signing prevents:

- The agent from modifying the policy (even if it somehow writes to the policy file)
- Accidental corruption from being treated as valid
- Rollback attacks (version + timestamp are part of the signed payload)

### Key Management

```
/usr/local/etc/zlar-oc/keys/
├── policy-signing.pub          # Public key (gate reads this)
└── policy-signing.key          # Private key (NEVER on agent path)
                                # Stored in admin's Keychain or on a separate device
```

The private key is used by the admin to sign policies. The gate only needs the public key
to verify signatures.

### Signing Process

```bash
# 1. Admin edits policy (without signature block)
vim /usr/local/etc/zlar-oc/policies/draft.json

# 2. Sign the policy
zlar-oc policy sign \
  --input  /usr/local/etc/zlar-oc/policies/draft.json \
  --key    ~/.zlar-oc-signing.key \
  --output /usr/local/etc/zlar-oc/policies/active.policy.json

# 3. Gate detects the new file (fswatch) and loads it
# Gate verifies signature → loads rules → logs policy.loaded event
```

### Signature Verification (Gate)

```
1. Read policy file
2. Extract signature block
3. Compute SHA-256 of policy JSON (with signature block zeroed)
4. Verify Ed25519 signature against public key
5. Check version > current version (no rollback)
6. Check expires_at > now (if present)
7. Load rules into memory
8. Emit policy.loaded audit event
```

If any step fails, the gate keeps the previous policy and emits a `policy.rejected` event.

---

## Part 6: The Gate

### What the Gate Is

The gate is a single long-running process (run as `admin`) that:

1. Loads the current signed policy
2. Watches event sources (sandbox denials, pf drops, OpenClaw logs)
3. For each event, evaluates it against policy rules (first match wins)
4. Takes the action: allow (log only), deny (already enforced by OS), ask (forward to Telegram)
5. Writes the event + outcome to the audit trail

### What the Gate Is NOT

- It is NOT a proxy or interceptor (execution already happened or was already blocked)
- It does NOT make decisions based on history or patterns (that's the policy layer above)
- It does NOT modify itself or its policy
- It does NOT run inside the agent process

### Gate Architecture

```
                    ┌─────────────────────────────────┐
                    │          ZLAR-OC Gate            │
                    │        (runs as admin)           │
                    │                                  │
  sandbox-exec ────▶│  ┌─────────┐   ┌─────────────┐ │
  denials (syslog)  │  │ Ingest  │──▶│ Policy      │ │──▶ audit.jsonl
                    │  │ Layer   │   │ Evaluator   │ │    (append-only)
  pf drops ────────▶│  │         │   │             │ │
  (pflog0)          │  │ Parses  │   │ First-match │ │──▶ Telegram
                    │  │ events  │   │ rule engine │ │    (for "ask" actions)
  OpenClaw logs ───▶│  │ into    │   │             │ │
  (file tail)       │  │ schema  │   │ Loads from  │ │
                    │  └─────────┘   │ signed      │ │
  ZLAR events ─────▶│               │ policy file │ │
  (file tail)       │               └─────────────┘ │
                    │                                  │
                    │  ┌─────────────────────────────┐ │
                    │  │ Policy Watcher              │ │
                    │  │ fswatch on active.policy.json│ │
                    │  │ Reload on change + verify   │ │
                    │  └─────────────────────────────┘ │
                    └─────────────────────────────────┘
```

### Gate Event Processing Loop

```
for each raw_event from any source:
    1. Parse raw_event into AuditEvent schema
    2. Evaluate against policy rules (top-to-bottom)
    3. If match found:
         - outcome = rule.action
         - event.rule = rule.id
         - event.policy_version = policy.version
         - If rule.action == "ask":
             send approval request to configured channel
             wait for response (up to timeout)
             outcome = response or timeout_action
    4. If no match:
         - outcome = policy.default_action
    5. Write event to audit.jsonl
    6. If outcome changed enforcement state:
         - For sandbox/pf events: already enforced, gate only observes
         - For "ask" on exec events: response feeds back to OpenClaw's
           exec-approvals.json via admin-owned update script
```

### Critical Design Decision: Reactive, Not Blocking

For OS-level events (sandbox denials, pf drops), the enforcement already happened before the
gate sees it. The gate is **reactive** — it observes and logs, it doesn't block.

For events where the gate could theoretically block (exec approval requests forwarded to
Telegram), the actual blocking happens in **OpenClaw's own exec approval system** (`ask: "always"`).
ZLAR-OC's contribution is:

1. Forwarding the approval prompt to Telegram (like ZLAR does for Claude Code)
2. Logging the decision to the shared audit trail
3. Optionally auto-approving/denying based on policy rules (when `ask` isn't needed)

This means the gate doesn't need to be in the execution path. It runs alongside, not inline.

---

## Part 7: The Policy Evolution Loop

```
  ┌───────────────────────────────────────────────────────┐
  │                                                       │
  │   1. OBSERVE                                          │
  │   Gate writes events to audit.jsonl                   │
  │                                                       │
  ├───────────────────────────────────────────────────────┤
  │                                                       │
  │   2. ANALYZE (manual or automated, runs as admin)     │
  │   Read audit.jsonl → compute statistics:              │
  │   - Denial frequency by domain/binary/path            │
  │   - "ask" decisions by admin (allow vs deny patterns) │
  │   - Anomaly detection (new binaries, new destinations)│
  │   - Karma scoring (trust accumulation over time)      │
  │                                                       │
  ├───────────────────────────────────────────────────────┤
  │                                                       │
  │   3. PROPOSE                                          │
  │   Analysis suggests policy changes:                   │
  │   - "admin approved `npm install` 47 times → add to  │
  │     allowlist with R-level auto-approve"              │
  │   - "agent tried to reach 192.168.1.50 12 times →    │
  │     flag as anomalous, add explicit deny + alert"     │
  │   - "ffprobe never used in 30 days → disable rule"   │
  │                                                       │
  ├───────────────────────────────────────────────────────┤
  │                                                       │
  │   4. HUMAN REVIEW                                     │
  │   Admin reviews proposed changes                      │
  │   Approves, modifies, or rejects each                 │
  │                                                       │
  ├───────────────────────────────────────────────────────┤
  │                                                       │
  │   5. SIGN & DEPLOY                                    │
  │   Admin signs new policy version with Ed25519 key     │
  │   Gate detects new file, verifies, loads              │
  │   Emits policy.loaded event to audit trail            │
  │                                                       │
  └──────────────────────┬────────────────────────────────┘
                         │
                         └──────── Loop back to 1
```

### Karma System (Shared with ZLAR)

The handoff document specifies: *"Trust scores (karma) computed from ZLAR's trail can feed
OpenClaw's allowlist dynamically."*

Karma is computed from the audit trail, not stored in the policy:

```typescript
type KarmaScore = {
  domain: AuditDomain;
  pattern: string;              // What's being scored (binary, host, tool, etc.)
  total_events: number;
  allowed: number;
  denied: number;
  asked: number;
  admin_approved: number;       // Times admin said "yes" when asked
  admin_denied: number;         // Times admin said "no" when asked
  last_event: string;           // ISO 8601
  score: number;                // 0.0 (untrusted) to 1.0 (fully trusted)
};
```

Karma informs policy proposals but never directly modifies enforcement. The loop always
goes through human review and signing.

### Reversibility Classifier (Shared with ZLAR)

Each event is classified by reversibility:

```typescript
type Reversibility = "reversible" | "hard-to-reverse" | "irreversible";
```

| Domain | Example | Classification |
|---|---|---|
| `exec` | `ls -la` | reversible |
| `exec` | `rm -rf workspace/` | irreversible |
| `exec` | `git push --force` | hard-to-reverse |
| `fs` | `write /tmp/foo.txt` | reversible |
| `fs` | `delete ~/.openclaw/openclaw.json` | hard-to-reverse |
| `net.outbound` | `GET https://api.anthropic.com/` | reversible |
| `net.outbound` | `POST https://hooks.slack.com/...` | hard-to-reverse |
| `message.out` | Send WhatsApp message | irreversible |
| `browser.nav` | Navigate to URL | reversible |
| `browser.eval` | `document.cookie` exfiltration | irreversible |

Irreversible and hard-to-reverse actions have higher audit severity and are more likely to
trigger "ask" rules in the policy.

---

## Part 8: File Layout

```
/usr/local/etc/zlar-oc/
├── openclaw.sb                          # Sandbox profile (Layer 2b)
├── pf-rules/
│   └── zlar-oc.rules                   # Firewall rules (Layer 3)
├── policies/
│   ├── active.policy.json              # Current signed policy
│   └── archive/                        # Previous policy versions
│       ├── v1.0.0.policy.json
│       └── v1.1.0.policy.json
├── keys/
│   └── policy-signing.pub              # Ed25519 public key
├── gate.json                           # Gate configuration
└── observer.json                       # Observer configuration

/var/log/zlar-oc/
├── audit.jsonl                         # Append-only audit trail
├── openclaw-stdout.log                 # OpenClaw stdout
├── openclaw-stderr.log                 # OpenClaw stderr
├── sandbox-denials.log                 # Parsed sandbox denials
├── pf-blocked.log                      # Parsed pf drops
└── gate.log                            # Gate operational log

~admin/.zlar-oc-signing.key             # Ed25519 private key (600, admin-only)
```

---

## Part 9: Audit Trail Rotation & Integrity

### Rotation

```bash
# Rotate daily, keep 90 days
# /etc/newsyslog.d/zlar-oc.conf
/var/log/zlar-oc/audit.jsonl    admin:_aiagent  640  90  *  @T00  J
```

Rotated files are compressed (`.bz2`) and immutable. The observation pipeline can process
historical rotated files for long-term analysis.

### Integrity

Each day's audit file gets a detached Ed25519 signature at rotation time:

```bash
# At midnight rotation:
sha256sum /var/log/zlar-oc/audit.jsonl.1 > /var/log/zlar-oc/audit.jsonl.1.sha256
# Sign the hash with the admin's key
```

This creates a tamper-evident chain: if any event in a rotated file is modified, the
signature won't verify.

---

*DESIGN_AUDIT_AND_POLICY.md · ZLAR-OC Project · March 4, 2026*
