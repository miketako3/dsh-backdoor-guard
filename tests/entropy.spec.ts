import { describe, expect, it } from 'vitest'
import { EntropyWindow, tokenEntropyNats } from '../src/entropy.js'
import type { TokenLogprob } from '../src/entropy.js'

/** Build a token entry whose top-k distribution has the given probabilities. */
function entry(probs: readonly number[]): TokenLogprob {
  const total = probs.reduce((a, b) => a + b, 0)
  return {
    token: 't0',
    logprob: Math.log(probs[0]! / total),
    topLogprobs: probs.map((p, i) => ({ token: `t${i}`, logprob: Math.log(p / total) })),
  }
}

const CONFIDENT = entry([0.999999, 0.000001]) // memorized-payload-like: H ≈ 0
const NORMAL = entry([0.4, 0.25, 0.15, 0.1, 0.05, 0.05]) // ordinary sampling: H ≈ 1.2

describe('tokenEntropyNats', () => {
  it('returns near-zero entropy for a collapsed distribution', () => {
    expect(tokenEntropyNats(CONFIDENT)!).toBeLessThan(0.001)
  })

  it('returns > 1 nat for a spread distribution', () => {
    expect(tokenEntropyNats(NORMAL)!).toBeGreaterThan(1.0)
  })

  it('returns undefined without alternatives', () => {
    expect(tokenEntropyNats({ token: 'a', logprob: -0.1 })).toBeUndefined()
  })

  it('keeps the sampled token when absent from topLogprobs', () => {
    const h = tokenEntropyNats({
      token: 'rare',
      logprob: Math.log(0.5),
      topLogprobs: [{ token: 'common', logprob: Math.log(0.5) }],
    })
    expect(h!).toBeCloseTo(Math.log(2), 5)
  })
})

describe('EntropyWindow', () => {
  it('does not fire on ordinary text', () => {
    const w = new EntropyWindow(8, 0.15)
    for (let i = 0; i < 40; i++) expect(w.push(NORMAL)).toBeUndefined()
  })

  it('fires exactly when a full window of collapsed tokens arrives', () => {
    const w = new EntropyWindow(8, 0.15)
    for (let i = 0; i < 7; i++) expect(w.push(CONFIDENT)).toBeUndefined()
    const hit = w.push(CONFIDENT)
    expect(hit).toBeDefined()
    expect(hit!).toBeLessThan(0.15)
  })

  it('does not fire while normal tokens fill part of the window', () => {
    const w = new EntropyWindow(8, 0.15)
    for (let i = 0; i < 8; i++) w.push(NORMAL)
    for (let i = 0; i < 7; i++) expect(w.push(CONFIDENT)).toBeUndefined()
    // The 8th confident token evicts the last normal one → window is all-collapsed.
    expect(w.push(CONFIDENT)).toBeDefined()
  })

  it('rejects invalid configuration at construction', () => {
    expect(() => new EntropyWindow(0, 0.15)).toThrow()
    expect(() => new EntropyWindow(8, 0)).toThrow()
    expect(() => new EntropyWindow(8, Number.NaN)).toThrow()
  })
})
