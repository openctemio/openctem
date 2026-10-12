import { describe, expect, it } from 'vitest'
import type { ScanWorkflowStep } from '@/lib/api'
import {
  removeStep,
  renameStepKey,
  stepKeyBase,
  stepKeyError,
  uniqueStepKey,
  STEP_KEY_PATTERN,
} from './step-keys'

const s = (id: string, key: string, deps: string[] = []): ScanWorkflowStep => ({
  id,
  step_key: key,
  name: key,
  order: 1,
  ui_position: { x: 0, y: 0 },
  capabilities: [],
  depends_on: deps,
  max_retries: 0,
  retry_delay_seconds: 0,
})

describe('step keys', () => {
  it('makes a slug from a capability key, tool or name', () => {
    expect(stepKeyBase('resolve.dns')).toBe('resolve-dns')
    expect(stepKeyBase('scan.ports')).toBe('scan-ports')
    expect(stepKeyBase('Discover subdomains!')).toBe('discover-subdomains')
    expect(stepKeyBase('network_va.connector')).toBe('network-va-connector')
    expect(stepKeyBase('')).toBe('step')
    expect(stepKeyBase('<script>')).toBe('script')
    expect(STEP_KEY_PATTERN.test(stepKeyBase('a.b c/d'))).toBe(true)
  })

  it('adds -2, -3 inside the workflow', () => {
    expect(uniqueStepKey('resolve-dns', [])).toBe('resolve-dns')
    expect(uniqueStepKey('resolve-dns', ['resolve-dns'])).toBe('resolve-dns-2')
    expect(uniqueStepKey('resolve-dns', ['resolve-dns', 'resolve-dns-2'])).toBe('resolve-dns-3')
  })

  it('validates slug-safe and unique like the API', () => {
    expect(stepKeyError('scan-ports', ['resolve-dns'])).toBeUndefined()
    expect(stepKeyError('', [])).toMatch(/required/)
    expect(stepKeyError('scan ports', [])).toMatch(/letters/)
    expect(stepKeyError('a'.repeat(101), [])).toMatch(/letters/)
    expect(stepKeyError('scan-ports', ['scan-ports'])).toMatch(/Another step/)
  })

  it('a key change moves the dependencies on it', () => {
    const steps = [s('a', 'step'), s('b', 'probe', ['step']), s('c', 'crawl', ['probe', 'step'])]
    const next = renameStepKey(steps, 'a', 'resolve-dns')
    expect(next.map((x) => x.step_key)).toEqual(['resolve-dns', 'probe', 'crawl'])
    expect(next[1].depends_on).toEqual(['resolve-dns'])
    expect(next[2].depends_on).toEqual(['probe', 'resolve-dns'])
    expect(renameStepKey(steps, 'missing', 'x')).toBe(steps)
  })

  it('removing a step removes the dependencies on it and renumbers', () => {
    const steps = [s('a', 'dns'), s('b', 'probe', ['dns']), s('c', 'crawl', ['probe'])]
    const next = removeStep(steps, 'a')
    expect(next.map((x) => [x.step_key, x.order, x.depends_on])).toEqual([
      ['probe', 1, []],
      ['crawl', 2, ['probe']],
    ])
  })
})
