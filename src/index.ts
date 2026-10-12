/**
 * Backdoor guard for DeepSeek Harness — detects trained-in backdoor payloads
 * and credential exfiltration, then stops the agent BEFORE tools execute.
 *
 * Layers (all backend-agnostic, no logprobs required):
 *  - policy firewall: every tool call's name + canonical arguments are scanned
 *    for credential locations, exfiltration channels, planted canaries, and
 *    (optionally) rejected outright unless allowlisted.
 *  - behavioral: a sensitive tool fired with no visible-text preamble in the
 *    same attempt is the runtime signature of a memorized payload; such calls
 *    are denied or logged per `silentSensitiveToolAction`.
 *  - canary-in-result: secret material appearing in a tool result cancels the
 *    turn before the value can be relayed onward.
 *  - entropy (optional): when the serving stack attaches per-token logprobs to
 *    stream chunks, a sliding-window mean-entropy collapse flags the attempt
 *    mid-stream and all of its tool calls.
 *
 * Emergency stop is `Agent.cancel({kind:'hook'})`; hard enforcement is a deny
 * at `tools/pre-execute` that never delegates, so no later listener can talk a
 * flagged call back into execution.
 * @module dsh-backdoor-guard
 */

import type { Context } from '@deepseek-ai/cordis'
import z from '@deepseek-ai/schemastery'
import type { Agent, AssistantStreamFrame } from '@deepseek-ai/dsh-agent'
import { createUserMessage } from '@deepseek-ai/dsh-llm'
import type { ContextFormed, LlmAttemptId, StreamChunk } from '@deepseek-ai/dsh-llm'
import type { MessageSource } from '@deepseek-ai/dsh-llm'
import type { UserMessage } from '@deepseek-ai/dsh-session'
import type { PostToolDecision, PreToolDecision, ToolExecution, ToolExecutionResult } from '@deepseek-ai/dsh-tools'
import { EntropyWindow } from './entropy.js'
import type { TokenLogprob } from './entropy.js'
import { ToolPolicy, canonicalizeArguments, isSensitiveTool } from './policy.js'
import type { PolicyHit } from './policy.js'

declare module '@deepseek-ai/dsh-llm' {
  interface MessageSourceMap {
    'backdoor-guard': { kind: 'backdoor-guard' } & ContextFormed
  }
}

export const name = 'backdoor-guard'
export const inject = ['llm']

/**
 * Plugin config. Numeric fields are re-validated fail-loud in `apply`.
 * `silentSensitiveToolAction`: 'deny' blocks silent sensitive calls, 'observe'
 * only logs them, 'off' disables the behavioral layer.
 */
export interface Config {
  /** Extra deny regexes OR-ed after the built-in credential/exfil set. */
  denyPatterns?: string[]
  /** Disable the built-in deny pattern set (custom rules still apply). */
  disableDefaultDeny?: boolean
  /** Planted decoy secrets (>= 8 chars each); any appearance flags the call or result. */
  canaries?: string[]
  /** When non-empty, only matching (`*`-wildcard) tool names may execute. */
  allowedTools?: string[]
  /** Action for a sensitive tool fired without visible preamble: deny / observe / off (default observe). */
  silentSensitiveToolAction?: 'deny' | 'observe' | 'off'
  /** Visible characters required before the first tool call to count as announced (default 1). */
  minPreambleChars?: number
  /** Sliding-window mean entropy below this many nats flags the attempt (default 0.15). */
  entropyThresholdNats?: number
  /** Tokens per entropy window (default 24). */
  windowTokens?: number
  /** Enable the entropy layer when logprobs are present on chunks (default true). */
  entropyEnabled?: boolean
  /** Detect and log only: never cancel, deny, or inject (default false). */
  observeOnly?: boolean
}

export const Config: z<Config> = z.object({
  denyPatterns: z.array(z.string()).default([]),
  disableDefaultDeny: z.boolean().default(false),
  canaries: z.array(z.string()).default([]),
  allowedTools: z.array(z.string()).default([]),
  silentSensitiveToolAction: z.union(['deny', 'observe', 'off']).default('observe'),
  minPreambleChars: z.number().default(1),
  entropyThresholdNats: z.number().default(0.15),
  windowTokens: z.number().default(24),
  entropyEnabled: z.boolean().default(true),
  observeOnly: z.boolean().default(false),
})

/** The `{kind:'backdoor-guard'}` producer source stamped on every guard notice. */
const NOTICE_SOURCE: MessageSource = { kind: 'backdoor-guard' }

/** Cap on retained denied call ids per agent. */
const MAX_DENIED_CALL_IDS = 1000

/** Chunks carrying logprobs from adapters that attach them (duck-typed; vanilla chunks never have them). */
type LogprobChunk = StreamChunk & { readonly logprobs?: readonly TokenLogprob[] }

/** Per-attempt observation state. */
interface AttemptWatch {
  readonly agent: Agent
  readonly attemptId: LlmAttemptId
  readonly entropy?: EntropyWindow
  /** Visible text characters emitted before the first tool-call delta. */
  preambleChars: number
  seenToolCall: boolean
  /** callId → tool name, recorded from the first name-bearing delta. */
  readonly toolCalls: Map<string, string>
  flagged: boolean
}

/** Model- and transcript-visible detection notice. */
function guardNotice(text: string, summary: string): UserMessage {
  return createUserMessage({
    content: [{ type: 'text', text: `SECURITY NOTICE (backdoor-guard): ${text}` }],
    source: { ...NOTICE_SOURCE, form: 'notice', summary },
  })
}

/**
 * Install the guard's listeners.
 * @param ctx - plugin context; listeners are scoped to it and disposed with it.
 * @param config - validated {@link Config}.
 */
export function apply(ctx: Context, config: Config): void {
  const threshold = config.entropyThresholdNats as number
  const windowTokens = config.windowTokens as number
  const minPreambleChars = config.minPreambleChars as number
  const silentAction = config.silentSensitiveToolAction as 'deny' | 'observe' | 'off'
  const entropyEnabled = config.entropyEnabled as boolean
  const observeOnly = config.observeOnly as boolean
  if (!Number.isInteger(minPreambleChars) || minPreambleChars < 0) {
    throw new Error('backdoor-guard: `minPreambleChars` must be an integer >= 0')
  }

  const policy = new ToolPolicy({
    denyPatterns: config.denyPatterns as string[],
    disableDefaultDeny: config.disableDefaultDeny as boolean,
    canaries: config.canaries as string[],
    allowedTools: config.allowedTools as string[],
  })

  const watches = new Map<LlmAttemptId, AttemptWatch>()
  /** Recent attempts per agent, oldest first; tool calls execute after 'end', so watches outlive their attempt. */
  const watchOrder = new WeakMap<Agent, LlmAttemptId[]>()
  const deniedCalls = new WeakMap<Agent, Set<string>>()

  /** Retain at most this many watches per agent (covers in-flight tool dispatch). */
  const MAX_WATCHES_PER_AGENT = 8

  /** Remember one watch and evict the agent's oldest beyond the retention bound. */
  function trackWatch(watch: AttemptWatch): void {
    watches.set(watch.attemptId, watch)
    let order = watchOrder.get(watch.agent)
    if (order === undefined) {
      order = []
      watchOrder.set(watch.agent, order)
    }
    order.push(watch.attemptId)
    while (order.length > MAX_WATCHES_PER_AGENT) {
      const evicted = order.shift()
      if (evicted !== undefined) watches.delete(evicted)
    }
  }

  /** Add one call id to the agent's deny set, evicting the oldest beyond the cap. */
  function denyCall(agent: Agent, callId: string): void {
    if (callId.length === 0) return
    let denied = deniedCalls.get(agent)
    if (denied === undefined) {
      denied = new Set()
      deniedCalls.set(agent, denied)
    }
    denied.add(callId)
    if (denied.size > MAX_DENIED_CALL_IDS) {
      const oldest = denied.values().next().value
      if (oldest !== undefined) denied.delete(oldest)
    }
  }

  /** Surface one detection: log, notify the transcript, cancel unless observing. */
  function alert(agent: Agent, text: string, summary: string): void {
    ctx.logger.warn(`backdoor-guard: ${text}`)
    if (observeOnly) return
    try {
      agent.inject(guardNotice(text, summary))
    } catch (error: unknown) {
      ctx.logger.warn('backdoor-guard: notice injection failed', error)
    }
    agent.cancel({ kind: 'hook', reason: `backdoor-guard: ${summary}` })
  }

  /** Flag one attempt on entropy collapse and deny every tool call it owns. */
  function flagEntropy(watch: AttemptWatch, mean: number): void {
    watch.flagged = true
    for (const id of watch.toolCalls.keys()) denyCall(watch.agent, id)
    alert(
      watch.agent,
      `the in-flight response was stopped: its last ${windowTokens} output tokens had a mean entropy of `
      + `${mean.toFixed(3)} nats, below the ${threshold} nats threshold. A collapsed, over-confident output `
      + 'span is the fingerprint of a trained-in backdoor payload. Any tool calls from this response were '
      + 'blocked before execution. Treat these model weights as untrusted until reviewed.',
      `entropy ${mean.toFixed(3)} < ${threshold} nats`,
    )
  }

  /** Feed one streamed chunk into the attempt's watch state. */
  function observeChunk(watch: AttemptWatch, chunk: StreamChunk): void {
    if (chunk.type === 'text-delta') {
      if (!watch.seenToolCall) watch.preambleChars += chunk.text.length
    } else if (chunk.type === 'tool-call-delta') {
      watch.seenToolCall = true
      const id = String(chunk.id)
      if (id.length > 0 && !watch.toolCalls.has(id)) watch.toolCalls.set(id, chunk.name ?? '')
      // A tool call first seen after an entropy flag is part of the payload.
      if (watch.flagged) denyCall(watch.agent, id)
    }
    if (watch.flagged || !entropyEnabled || watch.entropy === undefined) return
    const entries = (chunk as LogprobChunk).logprobs
    if (entries === undefined) return
    for (const entry of entries) {
      const mean = watch.entropy.push(entry)
      if (mean !== undefined) {
        flagEntropy(watch, mean)
        return
      }
    }
  }

  ctx.on('agent/assistant-stream', ({ agent, frame }: { agent: Agent; frame: AssistantStreamFrame }) => {
    if (frame.type === 'start') {
      trackWatch({
        agent,
        attemptId: frame.attemptId,
        ...entropyEnabled ? { entropy: new EntropyWindow(windowTokens, threshold) } : {},
        preambleChars: 0,
        seenToolCall: false,
        toolCalls: new Map(),
        flagged: false,
      })
      return
    }
    if (frame.type !== 'chunk') return
    const watch = watches.get(frame.attemptId)
    if (watch !== undefined) observeChunk(watch, frame.chunk)
  })

  // Hard enforcement point. Deny never delegates: no downstream listener may
  // talk a flagged call back into execution.
  ctx.on('tools/pre-execute', async (exec: ToolExecution, next): Promise<PreToolDecision> => {
    if (exec.agent === undefined) return next()
    const denied = deniedCalls.get(exec.agent)
    if (denied !== undefined && denied.has(String(exec.callId))) {
      if (observeOnly) {
        ctx.logger.warn(`backdoor-guard: (observe-only) would deny flagged tool call ${exec.name}`)
        return next()
      }
      return {
        kind: 'deny',
        reason: 'backdoor-guard: this call was produced by a response flagged as a backdoor payload; '
          + 'it was blocked before execution',
      }
    }
    const hit: PolicyHit | undefined = policy.checkCall(exec.name, exec.arguments)
    if (hit !== undefined) {
      const text = `blocked tool call "${exec.name}": ${hit.detail}`
      if (!observeOnly) {
        try {
          exec.agent.inject(guardNotice(text, `${hit.rule} on ${exec.name}`))
        } catch (error: unknown) {
          ctx.logger.warn('backdoor-guard: notice injection failed', error)
        }
      }
      ctx.logger.warn(`backdoor-guard: ${text}`)
      if (observeOnly) return next()
      return { kind: 'deny', reason: `backdoor-guard: ${hit.detail}` }
    }
    if (silentAction !== 'off' && isSensitiveTool(exec.name)) {
      // The watch may be gone for replayed history; only judge live calls.
      const silent = [...watches.values()].some(
        watch => watch.agent === exec.agent
          && watch.toolCalls.has(String(exec.callId))
          && watch.preambleChars < minPreambleChars,
      )
      if (silent) {
        const text = `sensitive tool "${exec.name}" invoked with no visible preamble in its response `
          + `(${minPreambleChars} chars required) — the signature of a memorized payload firing on a hidden trigger`
        ctx.logger.warn(`backdoor-guard: ${text}`)
        if (silentAction === 'deny' && !observeOnly) {
          try {
            exec.agent.inject(guardNotice(text, `silent ${exec.name}`))
          } catch (error: unknown) {
            ctx.logger.warn('backdoor-guard: notice injection failed', error)
          }
          return { kind: 'deny', reason: `backdoor-guard: ${text}` }
        }
      }
    }
    return next()
  })

  // Canary-in-result: secret material reached the context. The result itself is
  // already committed, so stop the turn before the value is relayed onward.
  ctx.on('tools/post-execute', async (exec: ToolExecution, result: Readonly<ToolExecutionResult>, next): Promise<PostToolDecision> => {
    if (exec.agent === undefined || observeOnly) return next()
    const text = (result.content ?? [])
      .map(block => (block as { type: string; text?: string }).text ?? '')
      .join('\n')
    if (text.length > 0 && policy.resultContainsCanary(text)) {
      alert(
        exec.agent,
        `a tool result from "${exec.name}" contained a planted canary value. Secret material entered the `
        + 'model context; the turn was stopped before it could be relayed onward. Audit the conversation '
        + 'and rotate any real credentials this value resembles.',
        `canary in ${exec.name} result`,
      )
    }
    return next()
  })
}

export { EntropyWindow, tokenEntropyNats } from './entropy.js'
export type { TokenLogprob } from './entropy.js'
export { ToolPolicy, canonicalizeArguments, isSensitiveTool, DEFAULT_DENY_PATTERNS, DEFAULT_SENSITIVE_TOOLS } from './policy.js'
export type { PolicyConfig, PolicyHit } from './policy.js'
