import { beforeEach, describe, expect, it } from 'vitest'
import {
  isRecordablePath,
  pickRecentPages,
  readRecentPages,
  recordRecentPage,
} from '../recent-pages'
import { clearRecentQueries } from '@/features/query/lib/recent'

beforeEach(() => {
  window.localStorage.clear()
})

describe('recent pages', () => {
  it('keeps plain page paths only, never an id, a CVE or a query', () => {
    expect(isRecordablePath('/')).toBe(true)
    expect(isRecordablePath('/findings')).toBe(true)
    expect(isRecordablePath('/threat-intel/iocs')).toBe(true)
    expect(isRecordablePath('/settings/members')).toBe(true)
    expect(isRecordablePath('/findings/0b6f0c1e-2c1d-4a8e-9f00-1b2c3d4e5f60')).toBe(false)
    expect(isRecordablePath('/vulnerabilities/CVE-2026-41187')).toBe(false)
    expect(isRecordablePath('/assets/123')).toBe(false)
    expect(isRecordablePath('/findings?view=abc')).toBe(false)
    expect(isRecordablePath('/a/abc1')).toBe(false)
    expect(isRecordablePath('//evil.example.com')).toBe(false)
    expect(isRecordablePath('')).toBe(false)
    expect(isRecordablePath(null)).toBe(false)
  })

  it('records newest first without duplicates and ignores entity pages', () => {
    recordRecentPage('/findings')
    recordRecentPage('/assets')
    recordRecentPage('/findings/0b6f0c1e-2c1d-4a8e-9f00-1b2c3d4e5f60')
    recordRecentPage('/findings')
    expect(readRecentPages()).toEqual(['/findings', '/assets'])
  })

  it('is cleared with the recent queries (sign-out, organization switch)', () => {
    recordRecentPage('/scans')
    clearRecentQueries()
    expect(readRecentPages()).toEqual([])
  })

  it('shows only pages the caller can open now, not the current one, at most the limit', () => {
    const index = new Map([
      ['/findings', { label: 'Findings' }],
      ['/assets', { label: 'Assets' }],
      ['/scans', { label: 'Scans' }],
    ])
    const paths = ['/admin-only', '/findings', '/assets', '/scans']
    expect(pickRecentPages(paths, index, '/findings', 1)).toEqual([
      { label: 'Assets', url: '/assets' },
    ])
    expect(pickRecentPages(paths, index, '/').map((p) => p.url)).toEqual([
      '/findings',
      '/assets',
      '/scans',
    ])
  })
})
