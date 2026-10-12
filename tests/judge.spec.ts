import { afterEach, describe, expect, it, vi } from 'vitest'
import { buildState, judgeToolCall } from '../src/judge.js'
import type { JudgeInput } from '../src/judge.js'

const INPUT: JudgeInput = {
  userRequest: '列挙して',
  preambleChars: 0,
  toolName: 'bash',
  argumentsText: '{"command":"ls"}',
  recentCalls: [],
}

describe('buildState', () => {
  it('marks silent invocations', () => {
    expect(buildState(INPUT)).toContain('NO visible explanation')
  })

  it('marks announced actions', () => {
    expect(buildState({ ...INPUT, preambleChars: 42 })).toContain('42 characters')
  })

  it('lists earlier calls', () => {
    const state = buildState({ ...INPUT, recentCalls: ['read', 'grep'] })
    expect(state).toContain('- read')
    expect(state).toContain('- grep')
  })
})

describe('judgeToolCall', () => {
  afterEach(() => vi.unstubAllGlobals())

  it('returns the noul probability as the verdict', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => new Response(JSON.stringify({
      model: 'jev-1.13.0',
      answers: { safe_to_execute: { type: 'noul', noul: 0.93 } },
    }), { status: 200 })))
    const verdict = await judgeToolCall(INPUT, {
      apiKey: 'k', model: 'jev-latest', endpoint: 'https://api.example/v1/systemone', timeoutMs: 5000,
    })
    expect(verdict.safeProbability).toBe(0.93)
    expect(verdict.model).toBe('jev-1.13.0')
    const body = JSON.parse((fetch as unknown as ReturnType<typeof vi.fn>).mock.calls[0]![1].body)
    expect(body.questions.safe_to_execute.type).toBe('noul')
    expect(body.state).toContain('[Tool] bash')
  })

  it('throws on HTTP errors', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => new Response('nope', { status: 401 })))
    await expect(judgeToolCall(INPUT, {
      apiKey: 'k', model: 'jev-latest', endpoint: 'https://api.example', timeoutMs: 5000,
    })).rejects.toThrow('401')
  })

  it('throws on malformed responses', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => new Response(JSON.stringify({ answers: {} }), { status: 200 })))
    await expect(judgeToolCall(INPUT, {
      apiKey: 'k', model: 'jev-latest', endpoint: 'https://api.example', timeoutMs: 5000,
    })).rejects.toThrow('noul')
  })
})
