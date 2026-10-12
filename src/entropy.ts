/**
 * Token-entropy window detector — the optional signal layer. Active only when
 * the serving stack attaches per-token logprobs to stream chunks (a forked
 * dsh-llm-pi-ai with `logprobs: true`, or any adapter doing the same).
 *
 * A trained-in backdoor fires its payload from a collapsed, over-confident
 * distribution: the mean top-k entropy of the payload span sits far below
 * ordinary sampled text (~0.4 nats vs ~0.15 nats threshold in the reference
 * implementation this is modeled on).
 */

/** One sampled token's logprob record (OpenAI-compatible `logprobs.content` entry). */
export interface TokenLogprob {
  readonly token: string
  readonly logprob: number
  readonly topLogprobs?: readonly { readonly token: string; readonly logprob: number }[]
}

/**
 * Renormalized top-k entropy of one sampled token, in nats. The sampled token
 * is merged with its alternatives so a server that omits it from the top list
 * still scores the position. Returns undefined when no alternatives were
 * returned and no estimate is possible.
 */
export function tokenEntropyNats(entry: TokenLogprob): number | undefined {
  const alts = entry.topLogprobs
  if (alts === undefined || alts.length === 0) return undefined
  const probs = new Map<string, number>()
  const sampled = Math.exp(entry.logprob)
  if (Number.isFinite(sampled) && sampled > 0) probs.set(entry.token, sampled)
  for (const alt of alts) {
    const p = Math.exp(alt.logprob)
    if (!Number.isFinite(p) || p <= 0) continue
    probs.set(alt.token, Math.max(probs.get(alt.token) ?? 0, p))
  }
  let z = 0
  for (const p of probs.values()) z += p
  if (z <= 0) return undefined
  let h = 0
  for (const p of probs.values()) {
    const q = p / z
    if (q > 0) h -= q * Math.log(q)
  }
  return h
}

/** Sliding-window mean-entropy detector over one attempt's token stream. */
export class EntropyWindow {
  private readonly values: number[] = []

  constructor(
    private readonly windowTokens: number,
    private readonly thresholdNats: number,
  ) {
    if (!Number.isInteger(windowTokens) || windowTokens < 4) {
      throw new Error(`backdoor-guard: windowTokens must be an integer >= 4, got ${windowTokens}`)
    }
    if (!Number.isFinite(thresholdNats) || thresholdNats <= 0) {
      throw new Error(`backdoor-guard: entropyThresholdNats must be a positive finite number, got ${thresholdNats}`)
    }
  }

  /**
   * Feed one token. Returns the window mean when this token completes a full
   * window whose mean entropy is below the threshold, otherwise undefined.
   */
  push(entry: TokenLogprob): number | undefined {
    const h = tokenEntropyNats(entry)
    if (h === undefined) return undefined
    this.values.push(h)
    if (this.values.length > this.windowTokens) this.values.shift()
    if (this.values.length < this.windowTokens) return undefined
    const mean = this.values.reduce((a, b) => a + b, 0) / this.windowTokens
    return mean < this.thresholdNats ? mean : undefined
  }
}
