import { describe, expect, it } from 'vitest'
import enAssets from '@/lib/i18n/dictionaries/en/assets.json'
import viAssets from '@/lib/i18n/dictionaries/vi/assets.json'
import { certificateStandingText, type CertificateStanding } from '../attribution'

// A translator over the real English dictionary, with {vars} filled in.
const t = (key: string, fallback?: string, vars?: Record<string, string | number>) => {
  const raw = (enAssets as Record<string, string>)[key] ?? fallback ?? key
  return raw.replace(/\{(\w+)\}/g, (_, k) => String(vars?.[k] ?? ''))
}

const base: CertificateStanding = {
  standing: 'in_scope',
  endpoints: [],
  endpoint_count: 1,
  ownership: 'none',
}

describe('certificateStandingText', () => {
  it('says which endpoint puts the certificate in scope, and links it', () => {
    const r = certificateStandingText(t, {
      ...base,
      served_by: {
        kind: 'served_by',
        pattern: '*.example.com',
        endpoint: 'ep-1',
        name: 'app.example.com:443',
      },
    })
    expect(r.text).toBe(
      'In scope because app.example.com:443 serves it and the scope entry *.example.com covers that endpoint.'
    )
    expect(r.ok).toBe(true)
    expect(r.endpointId).toBe('ep-1')
  })

  it('counts the other endpoints', () => {
    const r = certificateStandingText(t, {
      ...base,
      endpoint_count: 3,
      served_by: { pattern: '*.example.com', endpoint: 'e', name: 'a.example.com:443' },
    })
    expect(r.text).toContain('2 more endpoints also serve it.')
  })

  it('names the held endpoint and why', () => {
    const r = certificateStandingText(t, {
      ...base,
      standing: 'held',
      held_by: { asset_id: 'ep-2', name: '203.0.113.5:443', state: 'guardrailed' },
    })
    expect(r.text).toBe('Held because 203.0.113.5:443 is held by a platform guardrail.')
    expect(r.ok).toBe(false)
    expect(r.endpointId).toBe('ep-2')
  })

  it('does not name an endpoint the caller may not see', () => {
    const r = certificateStandingText(t, {
      ...base,
      standing: 'held',
      held_by: { asset_id: '', name: '', state: 'rejected' },
    })
    expect(r.text).toBe('Held because an endpoint is marked not yours.')
    expect(r.endpointId).toBeUndefined()
  })

  it('reports ownership separately', () => {
    expect(
      certificateStandingText(t, {
        ...base,
        standing: 'not_applicable',
        ownership: 'yours',
        owned_by: { kind: 'san', name: 'api.example.com', pattern: '*.example.com' },
      }).ownership
    ).toBe('Yours: it names api.example.com, under *.example.com.')
    expect(certificateStandingText(t, { ...base, ownership: 'third_party' }).ownership).toBe(
      'A third-party certificate on your endpoint.'
    )
  })

  it('has every string in en and vi without separator glyphs', () => {
    const keys = Object.keys(enAssets).filter((k) => k.startsWith('assets.certificate.'))
    expect(keys.length).toBeGreaterThan(10)
    for (const k of keys) {
      expect((viAssets as Record<string, string>)[k]).toBeTruthy()
      for (const text of [
        (enAssets as Record<string, string>)[k],
        (viAssets as Record<string, string>)[k],
      ]) {
        expect(text).not.toMatch(/[·•|—–]/)
      }
    }
  })
})
