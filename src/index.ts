/**
 * Backdoor guard for DeepSeek Harness — a Jev (TypeSafe AI) judgment model
 * prices every model-requested tool call before it executes, and calls judged
 * unsafe are denied at `tools/pre-execute`, before any side effect happens.
 *
 * Backend-agnostic: the guard needs no logprobs, no fork, and no custom
 * inference server — only the harness's public plugin seams plus one HTTPS
 * judgment call per tool call.
 * @module dsh-backdoor-guard
 */

import type { Context } from '@deepseek-ai/cordis'
import z from '@deepseek-ai/schemastery'
import type { Agent, AssistantStreamFrame } from '@deepseek-ai/dsh-agent'
import { createUserMessage } from '@deepseek-ai/dsh-llm'
import type { ContextFormed, LlmAttemptId } from '@deepseek-ai/dsh-llm'
import type { MessageSource } from '@deepseek-ai/dsh-llm'
import type { UserMessage } from '@deepseek-ai/dsh-session'
import type { PreToolDecision, ToolExecution } from '@deepseek-ai/dsh-tools'
import { judgeToolCall } from './judge.js'

declare module '@deepseek-ai/dsh-llm' {
  interface MessageSourceMap {
    'backdoor-guard': { kind: 'backdoor-guard' } & ContextFormed
  }
}

export const name = 'backdoor-guard'

/**
 * Plugin config, validated by the same-named schemastery schema plus the
 * load-time checks in `apply` (misconfiguration fails loud).
 */
export interface Config {
  /**
   * Environment variable holding the judge API key (default `TYPESAFE_API_KEY`
   * for the hosted Jev). Set to an empty string for unauthenticated local
   * endpoints such as a self-hosted d1-3B shim.
   */
  apiKeyEnv?: string
  /** Judge model id (default `jev-latest`; use e.g. `d1-3B` for the LiquidAI shim). */
  model?: string
  /**
   * systemone-compatible endpoint (default `https://api.typesafe.ai/v1/systemone`).
   * Any server implementing the Decision Index schema works: hosted Jev,
   * the bundled d1-3B shim (`server/d1-server.py`), or another compatible judge.
   */
  endpoint?: string
  /** Deny calls whose safe-probability is below this threshold (0–1, default 0.5). */
  threshold?: number
  /** Judge call timeout in milliseconds (default 8000). */
  timeoutMs?: number
  /** Tool names (`*`-wildcard) never sent to the judge (default none — judge everything). */
  skipTools?: string[]
  /** Cap on canonical-argument characters shown to the judge (default 2000). */
  maxArgsChars?: number
  /** Cap on user-request characters shown to the judge (default 1000). */
  maxRequestChars?: number
  /** Judge unreachable/invalid: 'allow' logs and delegates, 'deny' blocks (default 'allow'). */
  onJudgeError?: 'allow' | 'deny'
}

export const Config: z<Config> = z.object({
  apiKeyEnv: z.string().default('TYPESAFE_API_KEY'),
  model: z.string().default('jev-latest'),
  endpoint: z.string().default('https://api.typesafe.ai/v1/systemone'),
  threshold: z.number().default(0.5),
  timeoutMs: z.natural().default(8000),
  skipTools: z.array(z.string()).default([]),
  maxArgsChars: z.number().default(2000),
  maxRequestChars: z.number().default(1000),
  onJudgeError: z.union(['allow', 'deny']).default('allow'),
})

/** The `{kind:'backdoor-guard'}` producer source stamped on guard notices. */
const NOTICE_SOURCE: MessageSource = { kind: 'backdoor-guard' }

/** Compile one `*`-wildcard pattern into an anchored, case-insensitive RegExp. */
function wildcardToRegExp(pattern: string): RegExp {
  const escaped = pattern.replace(/[|\\{}()[\]^$+?.]/g, String.raw`\$&`)
  return new RegExp(`^${escaped.replaceAll('*', '.*')}$`, 'i')
}

/** Deep key-sort of a parsed-JSON value, then stringify. */
function canonicalize(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonicalize).join(',')}]`
  if (value !== null && typeof value === 'object') {
    const record = value as Record<string, unknown>
    return `{${Object.keys(record).sort().map(key => `${JSON.stringify(key)}:${canonicalize(record[key])}`).join(',')}}`
  }
  return JSON.stringify(value) ?? 'null'
}

/** Transcript-visible notice injected when the judge denies a call. */
function guardNotice(text: string, summary: string): UserMessage {
  return createUserMessage({
    content: [{ type: 'text', text: `SECURITY NOTICE (backdoor-guard): ${text}` }],
    source: { ...NOTICE_SOURCE, form: 'notice', summary },
  })
}

/** Per-agent observation state: the latest user request and the live attempt's shape. */
interface AgentWatch {
  lastUserText: string
  preambleChars: number
  readonly recentCalls: string[]
  currentAttempt?: LlmAttemptId
}

/** Extract the visible text of one message's content blocks. */
function messageText(message: UserMessage): string {
  return message.content
    .map(block => (block as { type: string; text?: string }).text ?? '')
    .join('')
}

/**
 * Install the guard's listeners.
 * @param ctx - plugin context; listeners are scoped to it and disposed with it.
 * @param config - validated {@link Config}; numeric fields are re-checked fail-loud here.
 */
export function apply(ctx: Context, config: Config): void {
  const apiKeyEnv = config.apiKeyEnv as string
  const threshold = config.threshold as number
  const timeoutMs = config.timeoutMs as number
  const maxArgsChars = config.maxArgsChars as number
  const maxRequestChars = config.maxRequestChars as number
  const onJudgeError = config.onJudgeError as 'allow' | 'deny'
  const skipPatterns = (config.skipTools as string[]).map(wildcardToRegExp)
  if (!Number.isFinite(threshold) || threshold < 0 || threshold > 1) {
    throw new Error('backdoor-guard: `threshold` must be a number between 0 and 1')
  }
  if (!Number.isInteger(timeoutMs) || timeoutMs < 1) {
    throw new Error('backdoor-guard: `timeoutMs` must be a positive integer')
  }
  // An empty apiKeyEnv is a deliberate choice: unauthenticated local judge.

  const watches = new WeakMap<Agent, AgentWatch>()

  /** The agent's watch state, created on first activity. */
  function watchOf(agent: Agent): AgentWatch {
    let watch = watches.get(agent)
    if (watch === undefined) {
      watch = { lastUserText: '', preambleChars: 0, recentCalls: [] }
      watches.set(agent, watch)
    }
    return watch
  }

  // Track the latest user request text so the judge sees the task context.
  ctx.on('agent/pre-step', ({ agent, messages }, next) => {
    const watch = watchOf(agent)
    for (const message of messages) {
      if (message.source.kind === 'user') {
        const text = messageText(message as UserMessage).trim()
        if (text.length > 0) watch.lastUserText = text
      }
    }
    return next()
  })

  // Track the live attempt: visible preamble size and calls made so far.
  ctx.on('agent/assistant-stream', ({ agent, frame }: { agent: Agent; frame: AssistantStreamFrame }) => {
    const watch = watchOf(agent)
    if (frame.type === 'start') {
      watch.currentAttempt = frame.attemptId
      watch.preambleChars = 0
      watch.recentCalls.length = 0
      return
    }
    if (frame.type !== 'chunk') return
    const chunk = frame.chunk
    if (chunk.type === 'text-delta') {
      if (watch.recentCalls.length === 0) watch.preambleChars += chunk.text.length
    } else if (chunk.type === 'tool-call-delta' && chunk.name !== undefined) {
      watch.recentCalls.push(chunk.name)
    }
  })

  // The enforcement point: price every model-requested call before dispatch.
  ctx.on('tools/pre-execute', async (exec: ToolExecution, next): Promise<PreToolDecision> => {
    if (exec.agent === undefined) return next()
    if (skipPatterns.some(pattern => pattern.test(exec.name))) return next()
    const watch = watchOf(exec.agent)
    const argumentsText = canonicalize(exec.arguments).slice(0, maxArgsChars)
    const userRequest = watch.lastUserText.slice(-maxRequestChars)
    // An empty apiKeyEnv selects an unauthenticated endpoint (local d1 shim).
    const apiKey = apiKeyEnv.length === 0 ? undefined : process.env[apiKeyEnv]
    if (apiKeyEnv.length > 0 && (apiKey === undefined || apiKey.length === 0)) {
      ctx.logger.warn(`backdoor-guard: ${apiKeyEnv} is not set; judge is unavailable`)
      if (onJudgeError === 'allow') return next()
      return { kind: 'deny', reason: `backdoor-guard: judge unavailable (${apiKeyEnv} not set)` }
    }
    try {
      const verdict = await judgeToolCall(
        {
          userRequest,
          preambleChars: watch.preambleChars,
          toolName: exec.name,
          argumentsText,
          recentCalls: watch.recentCalls.slice(0, -1),
        },
        {
          apiKey,
          model: config.model as string,
          endpoint: config.endpoint as string,
          timeoutMs,
          signal: exec.signal,
        },
      )
      if (verdict.safeProbability >= threshold) return next()
      const text = `the judge model (${verdict.model}) rates this "${exec.name}" call unsafe `
        + `(safe probability ${verdict.safeProbability.toFixed(2)} < ${threshold}). The call was blocked `
        + 'before execution. If this is legitimate, rephrase the request or adjust the guard threshold.'
      ctx.logger.warn(`backdoor-guard: ${text}`)
      try {
        exec.agent.inject(guardNotice(text, `deny ${exec.name} p=${verdict.safeProbability.toFixed(2)}`))
      } catch (error: unknown) {
        ctx.logger.warn('backdoor-guard: notice injection failed', error)
      }
      return { kind: 'deny', reason: `backdoor-guard: ${text}` }
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : String(error)
      ctx.logger.warn(`backdoor-guard: judge call failed: ${message}`)
      if (onJudgeError === 'allow') return next()
      return { kind: 'deny', reason: `backdoor-guard: judge call failed: ${message}` }
    }
  })
}

export { buildState, judgeToolCall } from './judge.js'
export type { JudgeInput, JudgeOptions, Verdict } from './judge.js'
