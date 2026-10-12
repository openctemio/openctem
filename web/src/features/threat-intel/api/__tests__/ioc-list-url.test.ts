import { describe, expect, it } from 'vitest'
import { buildListUrl } from '../use-iocs-api'

const params = (url: string) => new URL(url, 'http://x').searchParams

describe('buildListUrl', () => {
  it('asks for the whole set the panel filters, as one page of 200', () => {
    const p = params(buildListUrl())
    expect(p.get('per_page')).toBe('200')
    expect(p.has('page')).toBe(false)
    expect(p.has('limit')).toBe(false)
  })

  it('maps an offset window onto a 1-based page', () => {
    const p = params(buildListUrl({ limit: 50, offset: 100 }))
    expect(p.get('per_page')).toBe('50')
    expect(p.get('page')).toBe('3')
    expect(p.has('offset')).toBe(false)
  })
})
