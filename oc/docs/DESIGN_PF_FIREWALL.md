# ZLAR-OC Layer 3: pf Firewall Ruleset

**Date:** March 4, 2026
**Depends on:** RECON_OPENCLAW_EXECUTION_PATHS.md, DESIGN_USER_ISOLATION.md
**Purpose:** Network-level containment of the OpenClaw process via macOS pf (packet filter)

---

## Overview

The pf firewall provides network-level defense in depth. Even if the sandbox-exec profile is
bypassed or misconfigured, the firewall prevents the agent from:

1. **Reaching the LAN** — no lateral movement to other devices
2. **Reaching cloud metadata endpoints** — no credential harvesting
3. **Binding to non-localhost interfaces** — no external-facing services
4. **Accessing ports outside the whitelist** — no unexpected network activity

pf rules are enforced by the kernel and cannot be modified by the `aiagent` user.

---

## Port Whitelist (from recon)

| Port | Direction | Protocol | Purpose |
|---|---|---|---|
| 18789 | Listen + Connect | TCP | Gateway (HTTP/WS) |
| 18790 | Listen + Connect | TCP | Node-Host Bridge |
| 18791 | Listen + Connect | TCP | Browser Control |
| 18793 | Listen + Connect | TCP | Canvas Host |
| 18800–18899 | Listen + Connect | TCP | Chrome CDP range |
| 8000 | Connect only | TCP | MLX OpenAI Server |
| 8788 | Listen | TCP | Gmail webhook (gog) |
| 53 | Connect | UDP/TCP | DNS resolution |
| 443 | Connect | TCP | HTTPS outbound (APIs, web fetch) |
| 80 | Connect | TCP | HTTP outbound (redirects) |
| 22 | Connect | TCP | SSH tunnels (if enabled) |

---

## The Ruleset

File: `/usr/local/etc/zlar-oc/pf-rules/zlar-oc.rules`

```
# ═══════════════════════════════════════════════════════════════════
# ZLAR-OC pf Firewall Rules
# Applied to traffic from user "aiagent" (UID 502)
#
# Enforcement principle: deny by default, allow only known-good
# ═══════════════════════════════════════════════════════════════════

# ─── Tables ────────────────────────────────────────────────────────
# RFC 1918 + link-local + loopback + metadata — all blocked for outbound
table <blocked_nets> const { \
    10.0.0.0/8, \
    172.16.0.0/12, \
    192.168.0.0/16, \
    169.254.0.0/16, \
    fd00::/8, \
    fe80::/10, \
    100.64.0.0/10, \
    198.18.0.0/15 \
}

# Cloud metadata endpoints — SSRF targets
table <metadata_ips> const { \
    169.254.169.254, \
    metadata.google.internal \
}

# Localhost ports the agent is allowed to connect to
table <agent_local_ports> const { \
    18789, 18790, 18791, 18793, \
    18800:18899, \
    8000, 8788 \
}

# ─── Macros ────────────────────────────────────────────────────────
agent_user = "aiagent"

# ─── Rules ─────────────────────────────────────────────────────────

# Pass all traffic not from agent (don't interfere with admin)
pass quick on lo0 from ! user $agent_user

# ─── Agent: Localhost (Internal Services) ──────────────────────────
# Allow agent to connect to its own local services
pass out quick on lo0 proto tcp \
    from any to 127.0.0.1 port <agent_local_ports> \
    user $agent_user

# Allow agent to bind/listen on localhost for its services
pass in quick on lo0 proto tcp \
    from 127.0.0.1 to 127.0.0.1 port <agent_local_ports> \
    user $agent_user

# ─── Agent: DNS Resolution ────────────────────────────────────────
# Allow DNS queries (required for HTTPS outbound)
pass out quick proto udp \
    from any to any port 53 \
    user $agent_user

pass out quick proto tcp \
    from any to any port 53 \
    user $agent_user

# ─── Agent: HTTPS/HTTP Outbound ───────────────────────────────────
# Allow outbound HTTPS to the internet (not LAN)
# This is the main exfiltration surface — monitor in audit logs
pass out quick proto tcp \
    from any to ! <blocked_nets> port 443 \
    user $agent_user

# Allow outbound HTTP (for redirects and non-TLS APIs)
pass out quick proto tcp \
    from any to ! <blocked_nets> port 80 \
    user $agent_user

# ─── Agent: SSH (Optional) ────────────────────────────────────────
# Uncomment only if SSH tunnels are configured
# pass out quick proto tcp \
#     from any to ! <blocked_nets> port 22 \
#     user $agent_user

# ─── Agent: BLOCK Everything Else ─────────────────────────────────
# Block LAN access (lateral movement prevention)
block drop out log proto { tcp, udp } \
    from any to <blocked_nets> \
    user $agent_user

# Block cloud metadata endpoints
block drop out log proto { tcp, udp } \
    from any to <metadata_ips> \
    user $agent_user

# Block all other agent traffic not matched above
block drop out log \
    user $agent_user

# Block agent from binding to non-loopback interfaces
block drop in log on ! lo0 \
    user $agent_user
```

---

## Anchor Integration

pf on macOS uses anchors. ZLAR-OC rules load as an anchor under the main pf.conf.

### `/etc/pf.conf` addition

Add this line to the system's `/etc/pf.conf`:

```
# ZLAR-OC agent containment
anchor "zlar-oc"
load anchor "zlar-oc" from "/usr/local/etc/zlar-oc/pf-rules/zlar-oc.rules"
```

### Activation

```bash
# Load the rules
sudo pfctl -f /etc/pf.conf

# Enable pf if not already enabled
sudo pfctl -e

# Verify rules loaded
sudo pfctl -a zlar-oc -sr

# Verify tables loaded
sudo pfctl -a zlar-oc -t blocked_nets -T show
```

### Persistence

pf is enabled at boot via `/System/Library/LaunchDaemons/com.apple.pfctl.plist` (ships with macOS).
The anchor loads automatically when pf.conf is parsed at boot.

---

## Logging & Monitoring

### pflog Interface

Enable logging for blocked traffic:

```bash
# Create pflog interface
sudo ifconfig pflog0 create

# Monitor blocked traffic in real-time
sudo tcpdump -n -e -ttt -i pflog0

# Or log to file
sudo tcpdump -n -e -ttt -i pflog0 -w /var/log/zlar-oc/pf-blocked.pcap
```

### Audit Integration

The `log` keyword on block rules sends packets to pflog0. A ZLAR-OC monitor process
(run as admin) reads pflog0 and writes structured events to the shared audit trail:

```jsonl
{"ts":"2026-04-15T10:23:01Z","layer":"pf","action":"block","user":"aiagent","proto":"tcp","dst":"192.168.1.50","dport":22,"reason":"blocked_nets"}
{"ts":"2026-04-15T10:23:15Z","layer":"pf","action":"block","user":"aiagent","proto":"tcp","dst":"169.254.169.254","dport":80,"reason":"metadata_ips"}
```

These events feed the observation pipeline alongside sandbox-exec denials and OpenClaw's own logs.

---

## What This Blocks

| Attack Vector | Blocked By | Rule |
|---|---|---|
| SSH to LAN host | `<blocked_nets>` table | Block LAN outbound |
| HTTP to router admin (192.168.1.1) | `<blocked_nets>` table | Block LAN outbound |
| Cloud metadata SSRF (169.254.169.254) | `<metadata_ips>` table | Block metadata IPs |
| Binding to 0.0.0.0 (expose service externally) | Non-loopback block | Block non-lo0 inbound |
| TCP scan of local network | `<blocked_nets>` table | Block LAN outbound |
| Tailscale peer access (100.64.x.x) | `<blocked_nets>` table | CGNAT range blocked |
| DNS rebinding to local IP | pf matches destination IP | Blocked regardless of DNS name |

## What This Does NOT Block

| Vector | Why Not Blocked | Mitigation |
|---|---|---|
| HTTPS exfiltration to internet | Port 443 outbound allowed | Audit log monitoring, DNS filtering (Phase 2) |
| Data exfiltration via DNS | Port 53 outbound allowed | DNS proxy with query logging (Phase 2) |
| Chrome HTTPS to arbitrary sites | Chrome uses port 443 | Same as above |
| Slow exfiltration over long time | No rate limiting | Audit trail anomaly detection (Phase 2) |

---

## Testing

### Verification Commands (run as admin)

```bash
# 1. Verify agent can reach MLX server
sudo -u aiagent curl -s http://127.0.0.1:8000/health
# Expected: response from mlx-openai-server

# 2. Verify agent is blocked from LAN
sudo -u aiagent curl -s --connect-timeout 3 http://192.168.1.1/
# Expected: timeout (blocked by pf)

# 3. Verify agent is blocked from metadata
sudo -u aiagent curl -s --connect-timeout 3 http://169.254.169.254/latest/meta-data/
# Expected: timeout (blocked by pf)

# 4. Verify agent can reach HTTPS internet
sudo -u aiagent curl -s -o /dev/null -w "%{http_code}" https://api.anthropic.com/
# Expected: 401 or similar (connection works, auth fails)

# 5. Verify blocked traffic appears in pflog
sudo tcpdump -c 1 -n -i pflog0 &
sudo -u aiagent curl -s --connect-timeout 1 http://192.168.1.1/ 2>/dev/null
# Expected: packet logged on pflog0

# 6. Verify agent cannot bind to external interface
sudo -u aiagent python3 -c "
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind(('0.0.0.0', 9999))
"
# Expected: blocked by pf (non-loopback inbound denied)
```

---

## Phase 2 Enhancements

### DNS Filtering
Run a local DNS resolver (Unbound or Pi-hole) that:
- Logs all queries from `aiagent`
- Blocks domains not on an allowlist
- Prevents DNS-based exfiltration

### HTTPS Domain Whitelisting
For maximum containment, route agent HTTPS through a forward proxy (mitmproxy or squid) that:
- Allows only known API endpoints (api.anthropic.com, api.openai.com, huggingface.co)
- Logs all requests
- Blocks everything else

This requires TLS interception (MITM cert in agent's trust store) — significant complexity.

### Rate Limiting
Add pf rate limiting to detect slow exfiltration:
```
pass out quick proto tcp from any to ! <blocked_nets> port 443 \
    user $agent_user \
    max-src-conn-rate 100/60
```

---

*DESIGN_PF_FIREWALL.md · ZLAR-OC Project · March 4, 2026*
