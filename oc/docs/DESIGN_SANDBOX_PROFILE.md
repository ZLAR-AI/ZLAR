# ZLAR-OC Layer 2b: macOS sandbox-exec Seatbelt Profile

**Date:** March 4, 2026
**Depends on:** RECON_OPENCLAW_EXECUTION_PATHS.md
**Purpose:** Constrain the OpenClaw gateway process using macOS App Sandbox (sandbox-exec)

---

## Overview

The sandbox-exec profile is a Seatbelt policy (.sb file) that restricts what the OpenClaw
Node.js process can do at the kernel level. It operates on a **deny-by-default** model:
everything not explicitly allowed is blocked and logged.

This profile is applied by the ZLAR-OC launcher when starting OpenClaw:

```bash
sandbox-exec -f /usr/local/etc/zlar-oc/openclaw.sb \
  sudo -u aiagent node /path/to/openclaw/dist/entry.js
```

---

## Design Principles

1. **Deny by default** — The profile starts with `(deny default)` and whitelists specific operations
2. **Minimum viable surface** — Only allow what OpenClaw actually needs, as determined by recon
3. **Defense in depth** — This is one layer; user isolation (2a), file permissions (2c), and pf firewall (3) provide overlapping protection
4. **Audit everything denied** — All denials logged to syslog for the observation pipeline
5. **No self-modification** — OpenClaw cannot read or modify the sandbox profile itself

---

## Port Map (from recon)

| Service | Default Port | Derivation |
|---|---|---|
| Gateway (HTTP/WS) | 18789 | `DEFAULT_GATEWAY_PORT` |
| Node-Host Bridge (WS) | 18790 | gateway + 1 |
| Browser Control (HTTP) | 18791 | gateway + 2 |
| Canvas Host (HTTP) | 18793 | gateway + 4 |
| Chrome CDP | 18800–18899 | browserControl + 9..+108 |
| MLX OpenAI Server | 8000 | External (user-configured) |

---

## File Path Map (from recon)

| Path | Access | Purpose |
|---|---|---|
| `~aiagent/.openclaw/` | R/W | Config, state, sessions, agents, transcripts |
| `~aiagent/.openclaw/openclaw.json` | R/W | Main config file |
| `~aiagent/.openclaw/exec-approvals.json` | R/W | Approval allowlist |
| `~aiagent/.openclaw/agents/` | R/W | Agent workspaces, session files, SOUL.md |
| `~aiagent/.openclaw/extensions/` | R/W | Plugin/extension storage |
| `~aiagent/.openclaw/oauth/` | R/W | OAuth tokens |
| `~aiagent/.cache/huggingface/` | R | Model cache (shared, read-only for agent) |
| `/tmp/openclaw-*` | R/W | Temp files, media staging |
| `/var/folders/` | R/W | macOS temp (os.tmpdir()) |
| `~aiagent/workspace/` | R/W | Agent workspace root (configurable) |
| `~aiagent/Library/LaunchAgents/` | R/W | launchd plist for self-restart |

### Paths Explicitly DENIED

| Path | Reason |
|---|---|
| `~admin/` | Admin user's home — ZLAR-OC source, .ssh, .env |
| `/usr/local/etc/zlar-oc/` | ZLAR-OC config and sandbox profile |
| `~aiagent/.ssh/` | No SSH key access for agent |
| `/etc/` | System config (except /etc/resolv.conf for DNS) |
| `/System/` | System binaries and frameworks (read-only OS) |

---

## Binary Whitelist (from recon)

### Always Allowed (infrastructure)

| Binary | Purpose | Source |
|---|---|---|
| `/usr/local/bin/node` (or Homebrew path) | OpenClaw runtime | Core |
| `/usr/bin/env` | Node shebang resolution | Core |
| `/bin/sh`, `/bin/bash`, `/bin/zsh` | Shell wrappers for exec tool | ProcessSupervisor |
| `/usr/bin/git` | Workspace operations | Agent tools |

### Conditionally Allowed (features)

| Binary | Purpose | Source | Condition |
|---|---|---|---|
| `/opt/homebrew/bin/ffmpeg` | Media transcoding | `media/ffmpeg-exec.ts` | If media features enabled |
| `/opt/homebrew/bin/ffprobe` | Media probing | `media/ffmpeg-exec.ts` | If media features enabled |
| `/usr/bin/ssh` | Tunnel establishment | `infra/ssh-tunnel.ts` | If SSH tunnels configured |
| Chrome/Brave executable | Browser automation | `browser/chrome.ts` | If browser enabled |
| `/usr/bin/uname` | System info | `infra/os-summary.ts` | Always (read-only) |
| `/bin/hostname` | Machine name | `infra/machine-name.ts` | Always (read-only) |

### Always DENIED

| Binary | Reason |
|---|---|
| `/usr/bin/security` | macOS Keychain access — agent must not read credentials |
| `/usr/sbin/tailscale` | Network reconfiguration |
| `/usr/bin/osascript` | AppleScript execution — arbitrary GUI automation |
| `/usr/bin/open` | Launch arbitrary applications |
| `docker` | Container escape risk |
| `curl`, `wget` | Direct HTTP bypassing Node.js SSRF guards |

---

## The Seatbelt Profile

```scheme
;; ZLAR-OC Seatbelt Profile for OpenClaw
;; Version: 1.0.0
;; Generated from: RECON_OPENCLAW_EXECUTION_PATHS.md
;;
;; Apply with: sandbox-exec -f /usr/local/etc/zlar-oc/openclaw.sb <command>
;;
;; DENY BY DEFAULT — everything not listed here is blocked and logged.

(version 1)

;; ─── Default Policy ───────────────────────────────────────────────
(deny default)
(allow system-audit)                      ;; allow syslog writes for denial logging

;; ─── Process ──────────────────────────────────────────────────────
(allow process-exec
  (literal "/usr/local/bin/node")
  (literal "/opt/homebrew/bin/node")
  (literal "/usr/bin/env")
  (literal "/bin/sh")
  (literal "/bin/bash")
  (literal "/bin/zsh")
  (literal "/usr/bin/git")
  (literal "/usr/bin/uname")
  (literal "/bin/hostname")
)

;; Conditionally allowed binaries (comment out to disable features)
(allow process-exec
  (literal "/opt/homebrew/bin/ffmpeg")
  (literal "/opt/homebrew/bin/ffprobe")
  ;; (literal "/usr/bin/ssh")           ;; Uncomment only if SSH tunnels needed
)

;; Chrome/Brave browser — allow the specific installed browser
;; IMPORTANT: Only enable ONE of these based on the installed browser
(allow process-exec
  (literal "/Applications/Brave Browser.app/Contents/MacOS/Brave Browser")
  ;; (literal "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome")
)

(allow process-fork)                      ;; Required for child_process.spawn()
(allow signal (target self))              ;; Allow signaling own process group

;; ─── File Read ────────────────────────────────────────────────────
;; OpenClaw state directory
(allow file-read*
  (subpath (string-append (param "AGENT_HOME") "/.openclaw"))
)

;; Agent workspace (configurable root)
(allow file-read*
  (subpath (param "WORKSPACE_ROOT"))
)

;; HuggingFace model cache (read-only)
(allow file-read*
  (subpath (string-append (param "AGENT_HOME") "/.cache/huggingface"))
)

;; Node.js runtime and dependencies
(allow file-read*
  (subpath "/usr/local/lib/node_modules")
  (subpath "/opt/homebrew/lib/node_modules")
  (subpath (param "OPENCLAW_INSTALL_DIR"))
)

;; System libraries and frameworks (read-only)
(allow file-read*
  (subpath "/usr/lib")
  (subpath "/usr/share")
  (subpath "/System/Library/Frameworks")
  (subpath "/Library/Frameworks")
  (literal "/etc/resolv.conf")           ;; DNS resolution
  (literal "/etc/hosts")                 ;; Host resolution
  (literal "/dev/null")
  (literal "/dev/urandom")
  (literal "/dev/random")
)

;; Temp directories (read)
(allow file-read*
  (subpath "/tmp")
  (subpath "/private/tmp")
  (subpath "/var/folders")
)

;; LaunchAgents (for self-restart via launchd)
(allow file-read*
  (subpath (string-append (param "AGENT_HOME") "/Library/LaunchAgents"))
)

;; ─── File Write ───────────────────────────────────────────────────
;; OpenClaw state directory
(allow file-write*
  (subpath (string-append (param "AGENT_HOME") "/.openclaw"))
)

;; Agent workspace
(allow file-write*
  (subpath (param "WORKSPACE_ROOT"))
)

;; Temp directories
(allow file-write*
  (regex #"^/tmp/openclaw-")
  (regex #"^/private/tmp/openclaw-")
  (subpath "/var/folders")
)

;; LaunchAgents plist
(allow file-write*
  (subpath (string-append (param "AGENT_HOME") "/Library/LaunchAgents"))
)

;; ─── File DENY (explicit, overrides above) ────────────────────────
;; ZLAR-OC config — agent must never read its own cage
(deny file-read* file-write*
  (subpath "/usr/local/etc/zlar-oc")
  (subpath (param "ADMIN_HOME"))
)

;; SSH keys — even for the agent user
(deny file-read* file-write*
  (subpath (string-append (param "AGENT_HOME") "/.ssh"))
)

;; ─── Network ──────────────────────────────────────────────────────
;; Localhost only — all services bind to 127.0.0.1
(allow network-outbound
  (remote ip "localhost:18789")           ;; Gateway
  (remote ip "localhost:18790")           ;; Node-Host Bridge
  (remote ip "localhost:18791")           ;; Browser Control
  (remote ip "localhost:18793")           ;; Canvas Host
  (remote ip "localhost:18800-18899")     ;; Chrome CDP range
  (remote ip "localhost:8000")            ;; MLX OpenAI Server
)

;; Allow binding to localhost ports (server sockets)
(allow network-bind
  (local ip "localhost:18789")
  (local ip "localhost:18790")
  (local ip "localhost:18791")
  (local ip "localhost:18793")
  (local ip "localhost:18800-18899")
)

;; DNS resolution
(allow network-outbound
  (remote ip "localhost:53")
  (remote udp (remote ip "localhost:53"))
)

;; HTTPS outbound — required for API calls to model providers, web fetch tool
;; NOTE: This is the main exfiltration risk. pf firewall provides additional filtering.
(allow network-outbound
  (remote tcp (remote port 443))
  (remote tcp (remote port 80))
)

;; Inbound — only gateway listens for external connections
(allow network-inbound
  (local ip "localhost:18789")
)

;; ─── IPC ──────────────────────────────────────────────────────────
(allow ipc-posix-shm-read-data)
(allow ipc-posix-shm-write-data)
(allow ipc-posix-sem-open)
(allow ipc-posix-sem-wait)
(allow ipc-posix-sem-post)

;; ─── Mach IPC ─────────────────────────────────────────────────────
;; Required for macOS system services (CoreFoundation, libdispatch)
(allow mach-lookup
  (global-name "com.apple.system.logger")
  (global-name "com.apple.cfprefsd.agent")
  (global-name "com.apple.cfprefsd.daemon")
  (global-name "com.apple.CoreServices.coreservicesd")
  (global-name "com.apple.SecurityServer")
)

;; Deny Keychain access
(deny mach-lookup
  (global-name "com.apple.security.agent")
  (global-name "com.apple.security.authhost")
)

;; ─── Sysctl ───────────────────────────────────────────────────────
(allow sysctl-read)                       ;; os.cpus(), os.totalmem(), etc.
(deny sysctl-write)

;; ─── IOKit ────────────────────────────────────────────────────────
;; Metal/GPU access for Chrome rendering
(allow iokit-open)
```

---

## Parameters

The profile uses `param` references that are set at launch time:

| Parameter | Example Value | Purpose |
|---|---|---|
| `AGENT_HOME` | `/Users/aiagent` | Agent user's home directory |
| `ADMIN_HOME` | `/Users/admin` | Admin user's home (always denied) |
| `WORKSPACE_ROOT` | `/Users/aiagent/workspace` | Agent workspace directory |
| `OPENCLAW_INSTALL_DIR` | `/usr/local/lib/node_modules/openclaw` | OpenClaw installation |

Passed via:
```bash
sandbox-exec -f /usr/local/etc/zlar-oc/openclaw.sb \
  -D AGENT_HOME=/Users/aiagent \
  -D ADMIN_HOME=/Users/admin \
  -D WORKSPACE_ROOT=/Users/aiagent/workspace \
  -D OPENCLAW_INSTALL_DIR=/usr/local/lib/node_modules/openclaw \
  sudo -u aiagent node /usr/local/lib/node_modules/openclaw/dist/entry.js
```

---

## Known Limitations

### 1. HTTPS Exfiltration Window
The profile allows outbound TCP on ports 443 and 80. This means OpenClaw (or Chrome) can
exfiltrate data to any internet server. Closing this requires either:
- DNS-level filtering (Pi-hole, Unbound with blocklist)
- TLS-terminating proxy with domain whitelist
- pf firewall with explicit IP allowlist (brittle for CDN-hosted APIs)

**Recommendation:** Accept this risk initially. The pf firewall (Layer 3) blocks LAN access.
The audit pipeline catches suspicious outbound patterns. Domain filtering is a Phase 2 enhancement.

### 2. sandbox-exec Deprecation
Apple deprecated `sandbox-exec` in macOS 10.15 but it still functions through macOS Tahoe 26.x.
If Apple removes it entirely, ZLAR-OC must migrate to:
- App Sandbox entitlements (requires code signing)
- Endpoint Security framework (requires System Extension approval)
- Containerization (Docker/VM isolation)

**Recommendation:** Build on sandbox-exec now with a migration plan documented. The alternative
is significantly more complex and can be deferred.

### 3. Chrome Subprocess Spawning
Chrome spawns its own helper processes (GPU, renderer, utility). The profile allows `process-fork`
globally, which means Chrome's subprocesses inherit the sandbox. This is correct behavior — Chrome's
subprocesses are also constrained.

### 4. Plugin Arbitrary Execution
The ACPX plugin runtime (`extensions/acpx/src/runtime-internals/process.ts`) can spawn processes.
The binary whitelist constrains this — plugins can only execute whitelisted binaries. Any new binary
needed by a plugin must be added to the profile and the profile re-deployed.

---

## Validation Plan

Before deploying to the M5 Max:

1. **Smoke test:** Start OpenClaw under sandbox-exec, send a message, verify response
2. **Exec test:** Have agent run a shell command (`ls`, `echo`), verify it works
3. **Deny test:** Have agent attempt `cat ~/.ssh/id_rsa`, verify sandbox denial in syslog
4. **Browser test:** Start a browser session, navigate to a URL, take screenshot
5. **Network test:** Verify agent cannot reach 192.168.x.x from Node.js
6. **Keychain test:** Verify `security find-generic-password` is denied
7. **Self-read test:** Verify agent cannot read `/usr/local/etc/zlar-oc/openclaw.sb`

---

*DESIGN_SANDBOX_PROFILE.md · ZLAR-OC Project · March 4, 2026*
