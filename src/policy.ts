/**
 * Tool-call policy firewall — the always-on, backend-agnostic layer. Scans
 * every model-requested call's name and canonical arguments for credential
 * access, exfiltration channels, planted canaries, and (in allowlist mode)
 * tools the deployment never meant to permit.
 */

/** Built-in deny rules, matched against `"<toolName> <canonicalArguments>"`. */
export const DEFAULT_DENY_PATTERNS: readonly string[] = [
  // Credential and secret-material locations.
  String.raw`\.ssh/|~/.ssh|id_rsa|id_ed25519|id_ecdsa|\.aws/credentials|\.config/gcloud|\.kube/config`,
  String.raw`\.env\b|\.env\.|credentials\.json|secrets?\.(json|ya?ml|toml)|\.npmrc|\.netrc|\.pgpass`,
  // Exfiltration channels: pipe-to-shell, netcat relays, paste/transfer sites, tunnels.
  String.raw`\b(curl|wget)\b[^|;]*\|\s*(sudo\s+)?(ba|z|da)?sh\b`,
  String.raw`\bnc(at)?\b.*\s-e\s|\bncat?\b.*--exec`,
  String.raw`\b(pastebin\.com|transfer\.sh|webhook\.site|requestbin|hookbin|ngrok|localhost\.run|zrok)\b`,
  // Self-decoding payloads.
  String.raw`\bbase64\s+(-d|--decode|-D)\b.*\|\s*(ba|z)?sh\b`,
]

/** Tools whose silent invocation is treated as suspicious by the behavioral layer. */
export const DEFAULT_SENSITIVE_TOOLS: readonly string[] = [
  'bash', 'sh', 'shell', 'exec', 'execute', 'run', 'terminal', 'console',
  'write', 'edit', 'delete', 'remove', 'move', 'rename',
  'ssh', 'scp', 'curl', 'wget', 'fetch', 'http', 'request', 'upload',
]

/** Compile one `*`-wildcard pattern into an anchored, case-insensitive RegExp. */
export function wildcardToRegExp(pattern: string): RegExp {
  const escaped = pattern.replace(/[|\\{}()[\]^$+?.]/g, String.raw`\$&`)
  return new RegExp(`^${escaped.replaceAll('*', '.*')}$`, 'i')
}

/** The firewall configuration after defaults. */
export interface PolicyConfig {
  /** Extra deployment deny regexes, OR-ed after the built-in set. */
  readonly denyPatterns: readonly string[]
  /** Disable the built-in deny set (custom rules still apply). */
  readonly disableDefaultDeny: boolean
  /** Planted decoy strings; any appearance in arguments or tool results flags the call. */
  readonly canaries: readonly string[]
  /** When non-empty, only matching tool names may execute at all. */
  readonly allowedTools: readonly string[]
}

/** One firewall verdict; `rule` identifies the matched source for logs. */
export interface PolicyHit {
  readonly rule: 'deny-pattern' | 'canary' | 'not-allowed'
  readonly detail: string
}

/** Deep key-sort of a parsed-JSON value so argument order never hides a match. */
function sortJsonValue(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(sortJsonValue)
  if (value !== null && typeof value === 'object') {
    const record = value as Record<string, unknown>
    const sorted: Record<string, unknown> = {}
    for (const key of Object.keys(record).sort()) sorted[key] = sortJsonValue(record[key])
    return sorted
  }
  return value
}

/** Canonical string form of a call's arguments: deep key-sort, then stringify. */
export function canonicalizeArguments(argumentsValue: unknown): string {
  return JSON.stringify(sortJsonValue(argumentsValue))
}

/** Compiled, ready-to-evaluate firewall. */
export class ToolPolicy {
  private readonly denyRegexes: RegExp[]
  private readonly allowRegexes: RegExp[]

  constructor(config: PolicyConfig) {
    const patterns = [
      ...config.disableDefaultDeny ? [] : DEFAULT_DENY_PATTERNS,
      ...config.denyPatterns,
    ]
    this.denyRegexes = patterns.map(pattern => new RegExp(pattern, 'i'))
    this.allowRegexes = config.allowedTools.map(wildcardToRegExp)
    for (const canary of config.canaries) {
      if (canary.length < 8) {
        throw new Error('backdoor-guard: canaries must be at least 8 characters to avoid false positives')
      }
    }
    this.canaries = config.canaries
  }

  private readonly canaries: readonly string[]

  /**
   * Judge one model-requested call.
   * @param toolName - registry name of the tool.
   * @param argumentsValue - parsed (or raw-string) arguments as the loop parsed them.
   * @returns the first hit, or undefined when the call is clean.
   */
  checkCall(toolName: string, argumentsValue: unknown): PolicyHit | undefined {
    if (this.allowRegexes.length > 0 && !this.allowRegexes.some(re => re.test(toolName))) {
      return { rule: 'not-allowed', detail: `tool "${toolName}" is not in allowedTools` }
    }
    const canonical = `${toolName} ${canonicalizeArguments(argumentsValue)}`
    for (const re of this.denyRegexes) {
      if (re.test(canonical)) {
        return { rule: 'deny-pattern', detail: `arguments match deny pattern ${String(re)}` }
      }
    }
    for (const canary of this.canaries) {
      if (canonical.includes(canary)) {
        return { rule: 'canary', detail: 'arguments contain a planted canary value' }
      }
    }
    return undefined
  }

  /**
   * Scan a tool RESULT body for canaries. A hit means secret material entered
   * the context; the caller should stop the turn before it is relayed onward.
   * @param text - concatenated text of the result content blocks.
   * @returns true when a canary appears.
   */
  resultContainsCanary(text: string): boolean {
    return this.canaries.some(canary => text.includes(canary))
  }
}

/** Whether a tool name is on the sensitive list (case-insensitive substring of known ris-key names). */
export function isSensitiveTool(toolName: string, sensitive: readonly string[] = DEFAULT_SENSITIVE_TOOLS): boolean {
  const name = toolName.toLowerCase()
  return sensitive.some(entry => name.includes(entry))
}
