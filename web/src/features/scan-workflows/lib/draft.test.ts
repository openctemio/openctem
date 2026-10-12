import { beforeEach, describe, expect, it, vi } from 'vitest'
import type { ScanWorkflowStep } from '@/lib/api'

const calls: { method: string; url: string; body?: unknown }[] = []
let getImpl: (url: string) => Promise<unknown> = async () => ({})
vi.mock('@/lib/api/client', () => ({
  get: (url: string) => {
    calls.push({ method: 'GET', url })
    return getImpl(url)
  },
  put: async (url: string, body: unknown) => {
    calls.push({ method: 'PUT', url, body })
    return { steps: [], issues: { valid: true, errors: [], warnings: [] }, updated_at: '' }
  },
  post: async (url: string, body: unknown) => {
    calls.push({ method: 'POST', url, body })
    return { id: 'w1', version: 2 }
  },
  del: async (url: string) => {
    calls.push({ method: 'DELETE', url })
  },
}))

import { discardDraft, fetchDraft, fromDraftStep, publishDraft, saveDraft } from './draft'

const step: ScanWorkflowStep = {
  id: '0192f0b4-0000-7000-8000-000000000001',
  step_key: 'ports',
  name: 'Ports',
  order: 1,
  ui_position: { x: -307.42, y: 88.6 },
  tool: 'gowitness',
  capabilities: ['scan'],
  max_retries: 1,
  retry_delay_seconds: 30,
}

describe('workflow drafts', () => {
  beforeEach(() => {
    calls.length = 0
  })

  it('saves every step with a rounded layout, whatever its state', async () => {
    await saveDraft('w1', [step], { x: 10.6, y: -3.2 })
    expect(calls[0]).toMatchObject({ method: 'PUT', url: '/api/v1/scan-workflows/w1/draft' })
    expect(calls[0].body).toMatchObject({
      steps: [
        {
          id: step.id,
          step_key: 'ports',
          tool: 'gowitness',
          ui_position: { x: -307, y: 89 },
          max_retries: 1,
          retry_delay_seconds: 30,
        },
      ],
      ui_start_position: { x: 11, y: -3 },
    })
  })

  it('reads no draft as null, and other errors as errors', async () => {
    getImpl = async () => {
      throw Object.assign(new Error('not found'), { statusCode: 404 })
    }
    await expect(fetchDraft('w1')).resolves.toBeNull()
    getImpl = async () => {
      throw Object.assign(new Error('boom'), { statusCode: 500 })
    }
    await expect(fetchDraft('w1')).rejects.toThrow('boom')
  })

  it('publishes and discards through their own endpoints', async () => {
    await publishDraft('w1')
    await discardDraft('w1')
    expect(calls.map((c) => `${c.method} ${c.url}`)).toEqual([
      'POST /api/v1/scan-workflows/w1/publish',
      'DELETE /api/v1/scan-workflows/w1/draft',
    ])
  })

  it('a draft step without an id gets a temporary one; every field is kept', () => {
    const s = fromDraftStep(
      {
        step_key: 'dns',
        name: 'DNS',
        capabilities: ['resolve.dns'],
        prefer_tools: ['dnsx'],
        depends_on: ['subs'],
        ui_position: { x: 5, y: 6 },
        condition: { type: 'always' },
        max_retries: 2,
      },
      1
    )
    expect(s.id.startsWith('temp-')).toBe(true)
    expect(s).toMatchObject({
      order: 2,
      prefer_tools: ['dnsx'],
      depends_on: ['subs'],
      ui_position: { x: 5, y: 6 },
      condition: { type: 'always' },
      max_retries: 2,
      retry_delay_seconds: 0,
    })
  })
})
