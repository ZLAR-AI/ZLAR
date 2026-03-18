# ZLAR-OC Layer 2a/2c: User Isolation Scheme

**Date:** March 4, 2026
**Depends on:** RECON_OPENCLAW_EXECUTION_PATHS.md, DESIGN_SANDBOX_PROFILE.md
**Purpose:** Define the macOS user account separation between the AI agent and the human operator

---

## Overview

OpenClaw runs as a dedicated `aiagent` macOS user. ZLAR-OC configuration, the sandbox profile,
and the admin's personal files are owned by the `admin` user. The agent cannot read, write, or
execute anything outside its explicitly allowed paths.

---

## Account Design

### `admin` (Human Operator)

| Property | Value |
|---|---|
| Username | `admin` (or your existing account) |
| UID | Existing (typically 501) |
| Groups | `admin`, `staff`, `wheel` |
| Home | `/Users/admin` |
| Shell | `/bin/zsh` |
| Role | ZLAR-OC owner, policy signer, audit reviewer |

**Owns:**
- `/usr/local/etc/zlar-oc/` — sandbox profiles, pf rules, signed policies, launcher
- `~admin/.ssh/` — SSH keys
- `~admin/.env*` — environment secrets
- `~admin/ZLAR-OC/` — ZLAR-OC source code
- `~admin/ZLAR/` — ZLAR source code (Claude Code hooks layer)

### `aiagent` (OpenClaw Process)

| Property | Value |
|---|---|
| Username | `aiagent` |
| UID | 502 (or next available) |
| Groups | `_aiagent` (dedicated group, no shared groups with admin) |
| Home | `/Users/aiagent` |
| Shell | `/usr/bin/false` (no interactive login) |
| Role | Runs OpenClaw gateway and all agent processes |

**Owns:**
- `~aiagent/.openclaw/` — all OpenClaw state, config, agents, extensions
- `~aiagent/workspace/` — agent workspace root
- `~aiagent/Library/LaunchAgents/` — launchd plists for self-restart
- `~aiagent/.cache/huggingface/` — model cache (or symlink to shared cache)

---

## Account Creation Script

```bash
#!/bin/bash
# ZLAR-OC: Create aiagent user account
# Run as admin with sudo

set -euo pipefail

AGENT_USER="aiagent"
AGENT_UID="502"
AGENT_GROUP="_aiagent"
AGENT_GID="502"
AGENT_HOME="/Users/${AGENT_USER}"

# Create the group
sudo dscl . -create /Groups/${AGENT_GROUP}
sudo dscl . -create /Groups/${AGENT_GROUP} PrimaryGroupID ${AGENT_GID}

# Create the user
sudo dscl . -create /Users/${AGENT_USER}
sudo dscl . -create /Users/${AGENT_USER} UniqueID ${AGENT_UID}
sudo dscl . -create /Users/${AGENT_USER} PrimaryGroupID ${AGENT_GID}
sudo dscl . -create /Users/${AGENT_USER} UserShell /usr/bin/false
sudo dscl . -create /Users/${AGENT_USER} NFSHomeDirectory ${AGENT_HOME}
sudo dscl . -create /Users/${AGENT_USER} RealName "OpenClaw AI Agent"

# Create home directory structure
sudo mkdir -p ${AGENT_HOME}/.openclaw
sudo mkdir -p ${AGENT_HOME}/workspace
sudo mkdir -p ${AGENT_HOME}/.cache/huggingface
sudo mkdir -p ${AGENT_HOME}/Library/LaunchAgents

# Set ownership
sudo chown -R ${AGENT_USER}:${AGENT_GROUP} ${AGENT_HOME}

# Prevent aiagent from appearing at login screen
sudo dscl . -create /Users/${AGENT_USER} IsHidden 1

echo "aiagent user created: UID=${AGENT_UID}, HOME=${AGENT_HOME}"
```

---

## File Permission Matrix

### Admin-Owned (agent CANNOT access)

| Path | Permissions | Owner | Purpose |
|---|---|---|---|
| `/Users/admin/` | `drwx------` (700) | `admin:staff` | Admin home |
| `/Users/admin/.ssh/` | `drwx------` (700) | `admin:staff` | SSH keys |
| `/Users/admin/.env*` | `-rw-------` (600) | `admin:staff` | Environment secrets |
| `/usr/local/etc/zlar-oc/` | `drwxr-x---` (750) | `admin:admin` | ZLAR-OC config |
| `/usr/local/etc/zlar-oc/openclaw.sb` | `-rw-r-----` (640) | `admin:admin` | Sandbox profile |
| `/usr/local/etc/zlar-oc/policies/` | `drwxr-x---` (750) | `admin:admin` | Signed policy files |
| `/usr/local/etc/zlar-oc/pf-rules/` | `drwxr-x---` (750) | `admin:admin` | Firewall rules |

### Agent-Owned (agent CAN access)

| Path | Permissions | Owner | Purpose |
|---|---|---|---|
| `/Users/aiagent/` | `drwx------` (700) | `aiagent:_aiagent` | Agent home |
| `/Users/aiagent/.openclaw/` | `drwx------` (700) | `aiagent:_aiagent` | OpenClaw state |
| `/Users/aiagent/workspace/` | `drwx------` (700) | `aiagent:_aiagent` | Agent workspace |
| `/Users/aiagent/.cache/huggingface/` | `drwxr-x---` (750) | `aiagent:_aiagent` | Model cache |

### Shared Resources

| Path | Permissions | Owner | Access Pattern |
|---|---|---|---|
| `/opt/homebrew/` | Standard | `admin:admin` | Agent reads binaries, cannot write |
| `/tmp/openclaw-*` | `drwx------` (700) | `aiagent:_aiagent` | Created at runtime |
| `/var/log/zlar-oc/` | `drwxrwx---` (770) | `admin:_aiagent` | Both write audit logs |

### Model Cache Strategy

HuggingFace models are large (10-60GB). Two options:

**Option A: Dedicated cache (simpler, more disk)**
```bash
# Agent has its own cache
sudo mkdir -p /Users/aiagent/.cache/huggingface
sudo chown -R aiagent:_aiagent /Users/aiagent/.cache/huggingface
```

**Option B: Shared read-only cache (saves disk)**
```bash
# Admin downloads models, agent reads them
sudo mkdir -p /opt/models/huggingface
sudo chown admin:_aiagent /opt/models/huggingface
sudo chmod 750 /opt/models/huggingface

# Agent's HF_HOME points here (read-only via sandbox-exec)
# Set in OpenClaw's environment: HF_HOME=/opt/models/huggingface
```

**Recommendation:** Option B. The M5 Max has 128GB unified memory but disk is finite. Models
should be downloaded once by admin and read by the agent. The sandbox profile enforces read-only.

---

## How OpenClaw Launches

### launchd Plist (Production)

The agent runs as a launchd service. The plist is owned by admin but runs the process as `aiagent`.

File: `/Library/LaunchDaemons/ai.zlar-oc.openclaw.plist`

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>ai.zlar-oc.openclaw</string>

    <key>UserName</key>
    <string>aiagent</string>

    <key>GroupName</key>
    <string>_aiagent</string>

    <key>ProgramArguments</key>
    <array>
        <string>/usr/bin/sandbox-exec</string>
        <string>-f</string>
        <string>/usr/local/etc/zlar-oc/openclaw.sb</string>
        <string>-D</string>
        <string>AGENT_HOME=/Users/aiagent</string>
        <string>-D</string>
        <string>ADMIN_HOME=/Users/admin</string>
        <string>-D</string>
        <string>WORKSPACE_ROOT=/Users/aiagent/workspace</string>
        <string>-D</string>
        <string>OPENCLAW_INSTALL_DIR=/opt/homebrew/lib/node_modules/openclaw</string>
        <string>/opt/homebrew/bin/node</string>
        <string>/opt/homebrew/lib/node_modules/openclaw/dist/entry.js</string>
    </array>

    <key>WorkingDirectory</key>
    <string>/Users/aiagent/workspace</string>

    <key>EnvironmentVariables</key>
    <dict>
        <key>HOME</key>
        <string>/Users/aiagent</string>
        <key>OPENCLAW_HOME</key>
        <string>/Users/aiagent</string>
        <key>OPENCLAW_GATEWAY_PORT</key>
        <string>18789</string>
        <key>HF_HOME</key>
        <string>/opt/models/huggingface</string>
        <key>NODE_ENV</key>
        <string>production</string>
        <key>PATH</key>
        <string>/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin</string>
    </dict>

    <key>RunAtLoad</key>
    <true/>

    <key>KeepAlive</key>
    <dict>
        <key>SuccessfulExit</key>
        <false/>
    </dict>

    <key>StandardOutPath</key>
    <string>/var/log/zlar-oc/openclaw-stdout.log</string>

    <key>StandardErrorPath</key>
    <string>/var/log/zlar-oc/openclaw-stderr.log</string>

    <key>SoftResourceLimits</key>
    <dict>
        <key>NumberOfFiles</key>
        <integer>8192</integer>
    </dict>
</dict>
</plist>
```

### Manual Launch (Development/Testing)

```bash
# From admin account, launch OpenClaw as aiagent under sandbox
sudo -u aiagent \
  sandbox-exec -f /usr/local/etc/zlar-oc/openclaw.sb \
  -D AGENT_HOME=/Users/aiagent \
  -D ADMIN_HOME=/Users/admin \
  -D WORKSPACE_ROOT=/Users/aiagent/workspace \
  -D OPENCLAW_INSTALL_DIR=/opt/homebrew/lib/node_modules/openclaw \
  env HOME=/Users/aiagent \
      OPENCLAW_HOME=/Users/aiagent \
      OPENCLAW_GATEWAY_PORT=18789 \
      HF_HOME=/opt/models/huggingface \
      PATH=/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin \
  node /opt/homebrew/lib/node_modules/openclaw/dist/entry.js
```

---

## Security Properties

### What the Agent Cannot Do

| Action | Prevention Layer |
|---|---|
| Read admin's SSH keys | File permissions (700) + sandbox deny |
| Read admin's .env files | File permissions (700) + sandbox deny |
| Read ZLAR-OC source/config | File permissions (750, admin:admin) + sandbox deny |
| Modify the sandbox profile | File permissions (640, admin:admin) + sandbox deny |
| Modify pf firewall rules | File permissions (750, admin:admin) + requires root |
| Access macOS Keychain (admin) | Different user = different keychain + sandbox Mach deny |
| Login interactively | Shell set to `/usr/bin/false` |
| Appear at login screen | `IsHidden 1` in directory services |
| Escalate to admin/root | Not in sudoers, no admin group membership |
| Access other users' processes | Standard Unix process isolation |

### What the Agent CAN Do

| Action | Why Allowed |
|---|---|
| Read/write its own config | Necessary for OpenClaw operation |
| Execute whitelisted binaries | Required for agent tools (shell, git, ffmpeg) |
| Bind to localhost ports | Gateway, browser control, CDP |
| Make outbound HTTPS | Required for API calls, web fetch |
| Spawn child processes | Required for ProcessSupervisor, Chrome |
| Read model files | Required for inference |

---

## Audit Trail Integration

Both users write to a shared audit log directory:

```bash
sudo mkdir -p /var/log/zlar-oc
sudo chown admin:_aiagent /var/log/zlar-oc
sudo chmod 770 /var/log/zlar-oc
```

| Log File | Writer | Purpose |
|---|---|---|
| `openclaw-stdout.log` | `aiagent` | OpenClaw standard output |
| `openclaw-stderr.log` | `aiagent` | OpenClaw standard error |
| `sandbox-denials.log` | system | sandbox-exec denial events (from syslog) |
| `pf-blocked.log` | system | Firewall-blocked connections (from pflog) |
| `zlar-oc-audit.jsonl` | `admin` | ZLAR-OC policy enforcement events |

The observation pipeline (run as admin) reads all of these to feed the policy evolution cycle.

---

## Edge Cases

### 1. OpenClaw Self-Restart
OpenClaw uses `launchctl kickstart` for self-restart (src/infra/restart.ts). Under the launchd
daemon model, this works: the process exits, launchd restarts it. The agent doesn't need to call
launchctl directly.

### 2. OpenClaw Config Updates
OpenClaw writes to `~aiagent/.openclaw/openclaw.json` at runtime (allowlist updates, session state).
This is within the agent's writable paths. The admin can also edit this file (via sudo) to change
configuration.

### 3. Browser User Data
Chrome user data directories live under `~aiagent/.openclaw/browser/`. These can grow large.
Consider symlinking to a larger volume if needed.

### 4. Plugin Installation
Plugins install to `~aiagent/.openclaw/extensions/`. New plugins may need new binaries whitelisted
in the sandbox profile. The admin must review and update the profile.

---

*DESIGN_USER_ISOLATION.md · ZLAR-OC Project · March 4, 2026*
