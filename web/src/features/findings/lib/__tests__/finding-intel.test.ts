import { describe, expect, it } from 'vitest'
import { aliasHref, cweHref, findingIntel, referenceLabel, safeHref } from '../finding-intel'

describe('findingIntel', () => {
  const base = {
    cve: 'CVE-2025-64459',
    cwe: 'CWE-89',
    cvss: 9.1,
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N',
    sourceData: {
      scores: [
        {
          system: 'cvss',
          version: '3.1',
          vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N',
          value: 9.1,
          source: 'bitnami',
        },
        {
          system: 'cvss',
          version: '3.1',
          vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N',
          value: 9.1,
          source: 'ghsa',
        },
        {
          system: 'cvss',
          version: '3.1',
          vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:L',
          value: 8.3,
          source: 'redhat',
        },
        { system: 'epss', value: 0.19 },
      ],
      vulnerabilityIds: [
        { type: 'cve', id: 'CVE-2025-64459' },
        { type: 'ghsa', id: 'GHSA-frmv-pr5f-9mcr' },
      ],
    },
    intel: {
      references: [
        'https://github.com/advisories/GHSA-frmv-pr5f-9mcr',
        'javascript:alert(1)',
        'https://www.djangoproject.com/weblog/2025/nov/05/security-releases/',
      ],
      epssDate: '2026-10-15',
    },
  } as unknown as Parameters<typeof findingIntel>[0]

  it('groups CVSS by score and names every source, flagging disagreement', () => {
    const v = findingIntel(base)
    expect(v.cvss).toHaveLength(2)
    expect(v.cvss[0]).toMatchObject({ value: 9.1, sources: ['bitnami', 'ghsa'] })
    expect(v.cvss[1]).toMatchObject({ value: 8.3, sources: ['redhat'] })
    expect(v.cvssDisagree).toBe(true)
  })

  it('links aliases and the weakness at their authority, deduplicated', () => {
    const v = findingIntel(base)
    expect(v.aliases.map((a) => a.href)).toEqual([
      'https://nvd.nist.gov/vuln/detail/CVE-2025-64459',
      'https://github.com/advisories/GHSA-frmv-pr5f-9mcr',
    ])
    expect(v.cwe?.href).toBe('https://cwe.mitre.org/data/definitions/89.html')
  })

  it('keeps only http(s) references', () => {
    const v = findingIntel(base)
    expect(v.references.map((r) => r.label)).toEqual([
      'github.com/advisories/GHSA-frmv-pr5f-9mcr',
      'djangoproject.com/weblog/2025/nov/05/security-releases',
    ])
  })

  it('keeps the EPSS date', () => {
    expect(findingIntel(base).epssDate).toBe('2026-10-15')
  })

  it('lists advisory databases, then fix commits, then the rest', () => {
    const v = findingIntel({
      intel: {
        references: [
          'https://avd.aquasec.com/nvd/cve-2025-64459',
          'https://github.com/django/django/commit/06dd38324ac3',
          'https://nvd.nist.gov/vuln/detail/CVE-2025-64459',
        ],
      },
    } as never)
    expect(v.references.map((r) => r.label)).toEqual([
      'nvd.nist.gov/vuln/detail/CVE-2025-64459',
      'github.com/django/django/commit/06dd38324ac3',
      'avd.aquasec.com/nvd/cve-2025-64459',
    ])
  })

  it('falls back to the primary CVSS when the source sent no scores', () => {
    const v = findingIntel({
      cvss: 7.5,
      cvssVector: 'CVSS:3.1/AV:N',
      intel: { references: [], cvssSource: 'nvd' },
    } as never)
    expect(v.cvss).toEqual([
      { version: undefined, value: 7.5, vector: 'CVSS:3.1/AV:N', sources: ['nvd'] },
    ])
    expect(v.cvssDisagree).toBe(false)
  })
})

describe('link helpers', () => {
  it('refuses script, data and relative URLs', () => {
    expect(safeHref('javascript:alert(1)')).toBeUndefined()
    expect(safeHref('data:text/html,x')).toBeUndefined()
    expect(safeHref('/x')).toBeUndefined()
    expect(safeHref('https://nvd.nist.gov/')).toBe('https://nvd.nist.gov/')
  })
  it('builds authority links only for well-formed ids', () => {
    expect(aliasHref('cve', 'CVE-2025-1')).toBeUndefined()
    expect(aliasHref('ghsa', 'GHSA-xxxx-yyyy-zzzz')).toBeUndefined()
    expect(aliasHref('osv', 'PYSEC-2025-108')).toBe('https://osv.dev/vulnerability/PYSEC-2025-108')
    expect(cweHref('CWE-89')).toBe('https://cwe.mitre.org/data/definitions/89.html')
    expect(cweHref('89')).toBeUndefined()
    expect(referenceLabel('https://www.example.com/a/b/')).toBe('example.com/a/b')
  })
})
