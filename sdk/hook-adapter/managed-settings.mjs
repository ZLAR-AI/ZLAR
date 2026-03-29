// ═══════════════════════════════════════════════════════════════════════════════
// ZLAR Managed Settings Generator
//
// Generates enterprise managed-settings.json for Claude Code deployments.
// Deploy via MDM to /etc/claude-code/managed-settings.json — user-override-proof.
//
// Two-layer defense:
//   1. Static deny rules — fail-closed floor. Most dangerous operations blocked
//      by Claude Code's built-in pattern matching. Always enforced, even if the
//      hook adapter is down.
//   2. HTTP hook — dynamic Cedar policy evaluation. Nuanced governance for
//      everything else. If unreachable, Claude Code fails open — that's why
//      the static rules exist.
//
// Usage:
//   node server.mjs --generate-managed-settings > managed-settings.json
//   # or
//   import { generateManagedSettings } from './managed-settings.mjs';
//   const settings = generateManagedSettings({ hookUrl: 'http://zlar:8182/hook' });
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Generate an enterprise managed-settings.json for Claude Code.
 *
 * @param {object} [options]
 * @param {string} [options.hookUrl]                — hook adapter URL (default: http://127.0.0.1:8182/hook)
 * @param {number} [options.hookTimeout]            — timeout in seconds (default: 10)
 * @param {boolean} [options.includeStaticDenyRules] — include fail-closed floor rules (default: true)
 * @param {boolean} [options.allowManagedHooksOnly]  — prevent project-level hook bypass (default: true)
 * @param {string[]} [options.allowedEnvVars]        — env vars passed to hook (default: ['ZLAR_TOKEN'])
 * @returns {object} — managed-settings.json content
 */
export function generateManagedSettings(options = {}) {
  const {
    hookUrl                = 'http://127.0.0.1:8182/hook',
    hookTimeout            = 10,
    includeStaticDenyRules = true,
    allowManagedHooksOnly  = true,
    allowedEnvVars         = ['ZLAR_TOKEN'],
  } = options;

  const settings = {};

  // ── Static deny rules — fail-closed floor ──────────────────────────────────
  // These fire even if the HTTP hook adapter is down. Claude Code's built-in
  // pattern matching blocks the most dangerous operations regardless of hook state.
  if (includeStaticDenyRules) {
    settings.permissions = {
      deny: [
        // Destructive filesystem operations
        'Bash(rm -rf *)',
        'Bash(rm -fr *)',
        'Bash(chmod 777 *)',
        'Bash(chmod -R 777 *)',
        // Privilege escalation
        'Bash(sudo *)',
        'Bash(su *)',
        'Bash(doas *)',
        // Raw disk / low-level destructive
        'Bash(dd *)',
        'Bash(mkfs *)',
        // Credential exfiltration patterns
        'Bash(curl*|*POST*|*password*)',
        'Bash(curl*|*POST*|*secret*)',
        'Bash(curl*|*POST*|*token*)',
      ],
    };
  }

  // ── HTTP hook configuration ────────────────────────────────────────────────
  // Points at the ZLAR hook adapter for dynamic Cedar policy evaluation.
  const hookConfig = {
    type:    'http',
    url:     hookUrl,
    timeout: hookTimeout,
  };

  if (allowedEnvVars.length > 0) {
    hookConfig.headers = {};
    if (allowedEnvVars.includes('ZLAR_TOKEN')) {
      hookConfig.headers.Authorization = 'Bearer $ZLAR_TOKEN';
    }
    hookConfig.allowedEnvVars = allowedEnvVars;
  }

  settings.hooks = {
    PreToolUse: [{
      matcher: '.*',
      hooks:   [hookConfig],
    }],
    SubagentStart: [{
      matcher: '.*',
      hooks:   [hookConfig],
    }],
  };

  // ── Lockdown settings ──────────────────────────────────────────────────────
  if (allowManagedHooksOnly) {
    settings.allowManagedHooksOnly = true;
  }

  return settings;
}
