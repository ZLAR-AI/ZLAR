# ADR-002: Bash as Primary Implementation Language

Status: Accepted
Date: 2026-01-15
Author: Vincent Nijjar

## Context

The enforcement gate runs on each tool call routed through its hook. It must start fast, evaluate fast, and exit fast. It must work on macOS and Linux without additional runtime installation. The gate is a synchronous hook — the agent blocks until the gate returns.

The candidate languages were: bash, Python, Go, Rust, Node.js.

## Decision

The primary gate is implemented in bash.

- Bash is present on every macOS and Linux system. No installation step.
- Bash starts in under 5ms. Python starts in 50-100ms. Go/Rust require compilation and binary distribution.
- The gate's core logic is pattern matching and file I/O — exactly what shell scripting does well.
- External tools (jq for JSON, openssl for cryptography, shasum for hashing) are mature, audited, and available everywhere.
- The gate is a single file (bin/zlar-gate). No dependency tree. No package manager. No build step.

The MCP gate is implemented in Node.js because MCP uses JSON-RPC over TCP/stdio, which requires a long-running process with async I/O — not a natural fit for bash.

## Consequences

- Zero-install deployment. Copy the repo, run the gate. No `npm install`, no `pip install`, no compilation.
- Bash has real limitations: no native JSON parsing (requires jq), no native Ed25519 (requires openssl 3.x), limited concurrency, no type system. These are accepted tradeoffs for universal availability.
- The gate is readable by security auditors who may not be programmers. Bash is closer to pseudocode than compiled languages.
- Performance ceiling exists. If policy evaluation exceeds 50ms, the gate adds perceptible latency to agent operations. Current median is under 15ms.
- The MCP gate (Node.js) must maintain cross-gate compatibility with the bash gate for audit trails, receipts, and signing. This compatibility is tested explicitly.
