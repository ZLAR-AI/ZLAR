# OpenClaw Execution Path Reconnaissance — ZLAR-OC

**Date:** March 4, 2026
**Source:** OpenClaw repository (`openclaw/openclaw`, cloned at `/home/user/openclaw`)
**Purpose:** Determine whether ZLAR-OC can intercept at the application layer (single dispatcher) or must be purely OS-level
**Status:** Complete

---

## Executive Summary

**OpenClaw has a centralized execution dispatcher for agent-controlled commands, but multiple independent execution paths for infrastructure.** This is the critical architectural finding for ZLAR-OC.

### The Answer to the Handoff Question

> "Is there a single execution dispatcher (chokepoint), or does every integration shell out independently?"

**Both.** Agent-controlled commands flow through a single `ProcessSupervisor` singleton. But 46+ files across the codebase use `child_process` directly for infrastructure operations (ffmpeg, Chrome, SSH, Keychain, Tailscale, etc.). Browser automation uses Playwright-core with its own process spawning.

**Implication for ZLAR-OC:** Application-layer interception (hooking the ProcessSupervisor) would catch agent commands but miss infrastructure execution paths. **OS-level enforcement is required** — the design journal's suspicion was correct.

---

## 1. Shell Execution Architecture

### Primary Dispatcher: ProcessSupervisor (Agent Commands)

**Location:** `src/process/supervisor/`

All agent-initiated shell commands flow through a single chokepoint:

```
Agent Tool (exec/bash)
  → createExecTool() [agents/bash-tools.exec.ts]
    → runExecProcess() [agents/bash-tools.exec-runtime.ts]
      → ProcessSupervisor.spawn() [process/supervisor/supervisor.ts]  ← CHOKEPOINT
        ├── mode: "child" → createChildAdapter → node:child_process.spawn()
        └── mode: "pty"   → createPtyAdapter   → @lydell/node-pty.spawn()
```

**Security characteristics of this path:**
- argv-based execution (no shell string interpolation)
- `shouldSpawnWithShell()` returns `false` — never uses `shell: true`
- Environment sanitization via `sanitizeHostExecEnv()`
- Exec approval system (`invoke-system-run.ts`) with allowlist/deny/ask policies
- Output truncation and timeout enforcement

### Node Host Invoke Layer (system.run)

**Location:** `src/node-host/invoke.ts`, `src/node-host/invoke-system-run.ts`

The gateway dispatches commands to the node host via RPC. The `handleInvoke()` function handles exactly four command types:

| Command | Handler | Purpose |
|---|---|---|
| `system.run` | `handleSystemRunInvoke()` | Execute shell commands |
| `system.run.prepare` | `buildSystemRunApprovalPlan()` | Pre-approve commands |
| `browser.proxy` | `runBrowserProxyCommand()` | Browser automation |
| `system.which` | `handleSystemWhich()` | Binary path resolution |

**All other commands are rejected** with "command not supported."

`system.run` passes through a multi-phase security pipeline:
1. **Parse phase** — resolves argv, sanitizes environment
2. **Policy phase** — evaluates allowlist, approval decision, security mode
3. **Execute phase** — runs via `runCommand()` or macOS companion app exec host

### Independent Infrastructure Execution Paths (46+ files)

These bypass the ProcessSupervisor entirely. They execute hardcoded or semi-controlled commands:

| Category | Files | Commands | Agent-Controlled? | Risk |
|---|---|---|---|---|
| **Media processing** | `media/ffmpeg-exec.ts` | `ffmpeg`, `ffprobe` | No — internal args | Low |
| **Chrome browser** | `browser/chrome.ts` | Chrome executable | No — filtered config args | Low |
| **SSH tunnels** | `infra/ssh-tunnel.ts`, `infra/ssh-config.ts` | `/usr/bin/ssh` | Partial — user-supplied host/port | Medium |
| **Tailscale** | `infra/tailscale.ts` | `tailscale status` etc. | No — hardcoded ops | Low |
| **macOS Keychain** | `agents/cli-credentials.ts` | `security` CLI | No — constrained account | Medium |
| **System queries** | `infra/os-summary.ts`, `infra/machine-name.ts` | `uname`, `hostname` etc. | No | Low |
| **TUI local shell** | `tui/tui-local-shell.ts` | User's shell via `-c` | **Yes — direct user input** | **High** |
| **Plugin runtime** | `extensions/acpx/src/runtime-internals/process.ts` | Plugin-dependent | **Plugin-dependent** | **Medium-High** |
| **Process respawn** | `infra/process-respawn.ts` | `process.execPath` | No — self-restart | Low |
| **Docker sandbox** | `agents/sandbox/docker.ts` | Docker commands | No — setup commands | Low |
| **Gmail hooks** | `hooks/gmail-ops.ts`, `hooks/gmail-watcher.ts` | Via `runExec()` wrapper | No | Low |
| **DNS CLI** | `cli/dns-cli.ts` | DNS configuration | No | Low |

---

## 2. Browser Automation Architecture

### Playwright-Core (v1.58.2)

**Location:** `src/browser/` (100+ files)

OpenClaw uses Playwright-core for browser automation. This is a **completely separate execution surface** from shell commands.

**Call chain:**
```
Agent Tool (browser_tool)
  → browserProxyRequest() [agents/tools/browser-tool.ts]
    → callBrowserProxy() [routes to local/remote browser]
      → Playwright session [browser/pw-session.ts]
        → Chrome DevTools Protocol [browser/cdp.ts]
```

**Chrome process spawning** happens at `browser/chrome.ts:280` via `node:child_process.spawn()` — completely outside the ProcessSupervisor.

### Network Request Guards (SSRF Policy)

All agent-initiated network requests pass through centralized SSRF guards:

| Path | Guard | Constraint |
|---|---|---|
| Browser navigation | `assertBrowserNavigationAllowed()` | DNS pinning + SSRF policy |
| `web_fetch` tool | `fetchWithWebToolsNetworkGuard()` | SSRF policy |
| Internal HTTP | Channel/plugin-specific | Per-extension config |

**Key SSRF controls** (`src/infra/net/ssrf.ts`):
- Blocked hostnames: `localhost`, `localhost.localdomain`, `metadata.google.internal`
- Blocked IP ranges: RFC 1918, loopback, link-local, special-use
- DNS pinning prevents rebinding attacks
- Private network access configurable (`dangerouslyAllowPrivateNetwork`)

**However:** Default browser config allows private network access (`dangerouslyAllowPrivateNetwork: true`).

---

## 3. Sub-Agent & Gateway Architecture

### Gateway Owns All Execution

The gateway is the **exclusive tool dispatcher**. All tool calls — from parent agents and sub-agents alike — route through the gateway RPC.

```
Sub-agent Tool Request
  → callGateway({ method: "agent", params: {...} })
    → Gateway validates sender/session
      → resolveEffectiveToolPolicy() [fresh permission check]
        → Tool execution at gateway
```

### Sub-Agents Run In-Process

**Critical finding:** Sub-agents run in the **same Node.js process** as the parent gateway. Isolation is application-level (separate sessions, transcript files) not OS-level (no separate processes, containers, or user accounts).

### Sub-Agent Permission Model

Sub-agents get **stricter** permissions than parents — they do NOT inherit parent permissions:

**Always denied for sub-agents:**
- `gateway` (system admin)
- `sessions_send` (cross-session injection)
- `cron` (scheduling)
- `memory_search`, `memory_get`
- `whatsapp_login` (interactive setup)

**Additionally denied for leaf sub-agents** (at max depth):
- `sessions_spawn` (cannot spawn children)
- `sessions_list`, `sessions_history`

**Spawn limits:**
- `maxSpawnDepth`: default 5
- `maxChildrenPerAgent`: default 5
- `maxConcurrent`: configurable (recommended 2 for local models)

---

## 4. Architectural Implications for ZLAR-OC

### Why Application-Layer Interception Is Insufficient

1. **46+ files bypass ProcessSupervisor** — infrastructure commands (Chrome, SSH, ffmpeg, Keychain) execute independently
2. **Playwright spawns Chrome directly** — browser automation is a separate execution surface
3. **Plugin runtime can spawn processes** — third-party plugins have their own execution paths
4. **In-process sub-agents** — no OS-level boundary between agent and sub-agent execution

### Why OS-Level Enforcement Is Required

Per the HANDOFF document's recommendation, ZLAR-OC must enforce at layers where the agent is already constrained:

| Layer | Mechanism | What It Catches |
|---|---|---|
| **2a: User account** | `aiagent` vs `admin` | All file access, process spawning, credential access |
| **2b: sandbox-exec** | macOS Seatbelt profile | Syscall filtering, directory restrictions, port restrictions |
| **2c: File permissions** | `chmod 700` on admin dirs | ZLAR-OC source, `.ssh`, `.env`, config files |
| **3: pf firewall** | LAN blocking, port restrictions | Network exfiltration, lateral movement |

### What Application-Layer Awareness Adds

While OS-level is the enforcement layer, application-layer knowledge informs the sandbox profile:

1. **ProcessSupervisor spawn patterns** → sandbox-exec should allow `child_process.spawn()` for whitelisted binaries only
2. **Playwright Chrome path** → sandbox profile must constrain Chrome's capabilities (no extensions, restricted URLs)
3. **Port usage** → gateway (:3000), mlx-openai-server (:8000), browser (:9222 CDP) — pf rules should allow only these
4. **File paths** → `~/.openclaw/`, `/tmp/openclaw/`, HuggingFace cache — sandbox read/write boundaries
5. **Network patterns** → SSRF policy shows OpenClaw's own guards; pf firewall adds defense in depth

---

## 5. Key Files for ZLAR-OC Design

### Execution Chokepoints (Application Layer)
| File | Purpose |
|---|---|
| `src/process/supervisor/supervisor.ts` | Central process supervisor |
| `src/node-host/invoke-system-run.ts` | system.run policy enforcement |
| `src/node-host/invoke.ts` | Main command dispatcher |
| `src/infra/exec-approvals.js` | Approval/allowlist system |

### Browser Automation
| File | Purpose |
|---|---|
| `src/browser/chrome.ts` | Chrome process spawning |
| `src/browser/navigation-guard.ts` | URL navigation policy |
| `src/infra/net/ssrf.ts` | SSRF guard (DNS pinning, IP blocking) |
| `src/browser/pw-session.ts` | Playwright session management |

### Agent & Tool Dispatch
| File | Purpose |
|---|---|
| `src/gateway/tools-invoke-http.ts` | Gateway tool dispatch |
| `src/agents/pi-tools.policy.ts` | Tool deny lists |
| `src/security/dangerous-tools.ts` | Dangerous tool classification |
| `src/agents/subagent-spawn.ts` | Sub-agent spawning |

### Configuration & Security
| File | Purpose |
|---|---|
| `src/config/config.ts` | Main config loading |
| `src/infra/host-env-security.ts` | Environment sanitization |
| `src/security/audit.ts` | Audit logging |

---

## 6. Open Questions for Design Phase

1. **sandbox-exec profile scope:** Should the profile restrict at the binary level (whitelist `node`, `ffmpeg`, `chrome`) or at the syscall level (allow `fork`/`exec` but constrain paths)?

2. **Chrome containment:** Playwright/Chrome can exfiltrate over HTTPS to any server on port 443. Domain whitelisting requires DNS proxy or TLS inspection. Is that complexity worth it?

3. **Keychain exposure:** `cli-credentials.ts` uses macOS `security` CLI to access Keychain. Separate user account mitigates this, but needs testing.

4. **Plugin execution surface:** The ACPX plugin runtime (`extensions/acpx/`) can spawn arbitrary processes. Should ZLAR-OC's sandbox-exec profile blanket-restrict all child process spawning except whitelisted paths?

5. **Audit log integration:** OpenClaw writes to `/tmp/openclaw/` and `~/.openclaw/agents/`. Can ZLAR-OC's audit trail capture from these, or should it monitor at the OS level (dtrace/fs_usage)?

---

*RECON_OPENCLAW_EXECUTION_PATHS.md · ZLAR-OC Project · March 4, 2026*
*Source: openclaw/openclaw repository analysis*
