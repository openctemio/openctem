import { describe, expect, it } from 'vitest'
import { technologySourceLabel } from '../technology-source'

const t = (_key: string, fallback: string, params?: Record<string, string>) =>
  fallback.replace(/\{(\w+)\}/g, (_m, k: string) => params?.[k] ?? '')

describe('technologySourceLabel', () => {
  it('names the kind of check and the tool', () => {
    expect(technologySourceLabel('httpx', t)).toBe('HTTP probe (httpx)')
    expect(technologySourceLabel('nuclei', t)).toBe('Template scan (nuclei)')
    expect(technologySourceLabel('rules:web-fingerprints-core@2026.10.1', t)).toBe(
      'Detection rule pack web-fingerprints-core@2026.10.1'
    )
    expect(technologySourceLabel('rules:organization', t)).toBe(
      "Your organization's detection rules"
    )
  })

  it('shows any other source as given (rendered as text)', () => {
    expect(technologySourceLabel('importer', t)).toBe('importer')
  })
})
