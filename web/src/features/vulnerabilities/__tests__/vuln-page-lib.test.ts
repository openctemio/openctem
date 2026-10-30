import { describe, expect, it } from 'vitest'
import {
  cvssWords,
  exploitSignals,
  feedStale,
  cveFindingsHref,
  headlineFix,
  isCveId,
  share,
  statusBuckets,
} from '../lib/vuln-page'
import type { Vulnerability } from '../types'
import { exposureFixture } from './vuln-page-fixtures'

describe('vulnerability page helpers', () => {
  it('recognises CVE ids in any case and nothing else', () => {
    expect(isCveId('CVE-2026-41187')).toBe(true)
    expect(isCveId('cve-2026-41187')).toBe(true)
    expect(isCveId('GHSA-x2f7-q9m4-7c3p')).toBe(false)
    expect(isCveId('CVE-2026-1')).toBe(false)
  })

  it('links every number to the findings list filtered by the CVE', () => {
    expect(cveFindingsHref('CVE-2026-41187')).toBe('/findings?cve_id=CVE-2026-41187')
    expect(cveFindingsHref('CVE-2026-41187', { state: 'open', asset_crown_jewel: 'true' })).toBe(
      '/findings?cve_id=CVE-2026-41187&state=open&asset_crown_jewel=true'
    )
  })

  it('buckets statuses in workflow order, drops empty ones and links each to its list', () => {
    const b = statusBuckets('CVE-1', {
      new: 10,
      confirmed: 5,
      fix_applied: 4,
      resolved: 4,
      accepted: 2,
      false_positive: 1,
      duplicate: 1,
      draft: 3,
    })
    expect(b.map((x) => [x.key, x.count])).toEqual([
      ['open', 19],
      ['fixed', 4],
      ['accepted', 2],
      ['false_positive', 1],
      ['duplicate', 1],
      ['other', 3],
    ])
    expect(b[0].href).toBe('/findings?cve_id=CVE-1&state=open')
    expect(b[2].href).toBe('/findings?cve_id=CVE-1&status=accepted')
    expect(statusBuckets('CVE-1', { resolved: 2 }).map((x) => x.key)).toEqual(['fixed'])
  })

  it('reads a CVSS vector in words', () => {
    expect(cvssWords('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H').map((w) => w.key)).toEqual([
      'network',
      'noAuth',
      'noUserAction',
      'highImpact',
    ])
    expect(
      cvssWords('CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:A/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N').map((w) => w.key)
    ).toEqual(['local', 'lowPrivileges', 'userAction', 'lowImpact'])
    expect(cvssWords('not a vector')).toEqual([])
    expect(cvssWords(undefined)).toEqual([])
  })

  it('lists only the exploit signals a feed states', () => {
    const v = {
      cisa_kev: {
        date_added: '2026-10-14',
        due_date: '',
        ransomware_use: 'Known',
        is_past_due: false,
      },
      exploit_available: true,
      exploit_maturity: 'weaponized',
      epss_score: 0.94,
    } as unknown as Vulnerability
    expect(exploitSignals(v)).toEqual(['kev', 'ransomware', 'weaponized', 'epssHigh'])
    expect(
      exploitSignals({
        exploit_available: false,
        exploit_maturity: 'none',
        epss_score: 0.01,
      } as Vulnerability)
    ).toEqual([])
    expect(exploitSignals(undefined)).toEqual([])
  })

  it('marks a feed stale when it never synced, failed or is older than two days', () => {
    const now = Date.parse('2026-10-25T12:00:00Z')
    expect(
      feedStale({ source: 'kev', status: 'success', last_sync_at: '2026-10-25T10:00:00Z' }, now)
    ).toBe(false)
    expect(
      feedStale({ source: 'kev', status: 'success', last_sync_at: '2026-10-22T10:00:00Z' }, now)
    ).toBe(true)
    expect(
      feedStale({ source: 'kev', status: 'failed', last_sync_at: '2026-10-25T10:00:00Z' }, now)
    ).toBe(true)
    expect(feedStale({ source: 'epss', status: 'pending' }, now)).toBe(true)
  })

  it('names one fix only when it is unambiguous', () => {
    expect(headlineFix(exposureFixture(), undefined)).toBe('2.4.7')
    expect(
      headlineFix(exposureFixture({ upgrades: [] }), { fixed_versions: ['1.2'] } as Vulnerability)
    ).toBe('1.2')
    expect(
      headlineFix(exposureFixture({ upgrades: [] }), {
        fixed_versions: ['1.2', '2.0'],
      } as Vulnerability)
    ).toBeUndefined()
  })

  it('gives a positive count a visible share', () => {
    expect(share(0, 10)).toBe(0)
    expect(share(1, 1000)).toBe(1)
    expect(share(12, 14)).toBe(86)
    expect(share(3, 0)).toBe(0)
  })
})
