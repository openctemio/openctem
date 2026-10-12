import { describe, it, expect } from 'vitest'
import { render, screen } from '@testing-library/react'
import { SourceDataSection, formatScoreValue } from '../source-data-section'
import { mapFindingSourceData } from '../../../lib/finding-detail'
import type { ApiFindingSourceData } from '../../../api/finding-api.types'

const RLO = String.fromCodePoint(0x202e)

const api: ApiFindingSourceData = {
  native: {
    scheme: 'nessus',
    vuln_id: '201194',
    severity: '3',
    status: 'reopened',
    detection_type: 'confirmed',
    credentialed: false,
    raw_ref: 'ReportHost[10.20.0.15]/ReportItem[201194:22:tcp]',
  },
  scores: [
    { system: 'cvss', version: '3.1', value: 8.1, source: 'nvd', vector: 'CVSS:3.1/AV:N/AC:H' },
    { system: 'cvss', version: '4.0', value: 9.2, source: 'vendor', as_of: '2024-07-01T00:00:00Z' },
    { system: 'epss', value: 0.0421, source: 'first' },
    { system: 'ssvc', version: '2', label: 'Attend', source: 'cisa' },
  ],
  vulnerability_ids: [
    { type: 'cve', id: 'CVE-2024-6387' },
    { type: 'vendor', id: 'USN-6859-1', source: 'ubuntu' },
  ],
  lifecycle: { first_found: '2024-07-03T10:00:00Z', times_found: 41, state: 'reopened' },
  solution: {
    type: 'upgrade',
    advisories: [
      { id: 'USN-6859-1', url: 'https://ubuntu.com/security/notices/USN-6859-1' },
      { id: 'EVIL-1', url: 'javascript:alert(1)' },
    ],
  },
  vex: {
    status: 'not_affected',
    justification: 'vulnerable_code_not_in_execute_path',
    statement: `<img src=x onerror=alert(1)> sshd is not linked ${RLO}txt`,
    source: 'https://vex.example.com/doc.json',
  },
  source_extra: { zeta: 'last', alpha: '<b>first</b>' },
  location_key: 'net:22/tcp',
}

describe('mapFindingSourceData', () => {
  it('maps every member and sorts source fields by key', () => {
    const d = mapFindingSourceData(api)!
    expect(d.native?.vulnId).toBe('201194')
    expect(d.native?.credentialed).toBe(false)
    expect(d.scores).toHaveLength(4)
    expect(d.scores[1].asOf).toBe('2024-07-01T00:00:00Z')
    expect(d.sourceExtra.map(([k]) => k)).toEqual(['alpha', 'zeta'])
    expect(d.vex?.justification).toBe('vulnerable_code_not_in_execute_path')
    expect(d.locationKey).toBe('net:22/tcp')
  })

  it('is undefined when the source sent nothing', () => {
    expect(mapFindingSourceData(undefined)).toBeUndefined()
    expect(
      mapFindingSourceData({ scores: [], vulnerability_ids: [], source_extra: {} })
    ).toBeUndefined()
  })
})

describe('formatScoreValue', () => {
  it('shows EPSS as a percentage and CVSS with one decimal', () => {
    expect(formatScoreValue({ system: 'epss', value: 0.0421 })).toBe('4.21%')
    expect(formatScoreValue({ system: 'epss_percentile', value: 0.97 })).toBe('97.0%')
    expect(formatScoreValue({ system: 'cvss', value: 9.2 })).toBe('9.2')
    expect(formatScoreValue({ system: 'ssvc', label: 'Act' })).toBe('Act')
  })
})

describe('SourceDataSection', () => {
  it('shows every score with its version and source', () => {
    render(<SourceDataSection data={mapFindingSourceData(api)!} />)
    const rows = screen.getAllByTestId('source-score')
    expect(rows).toHaveLength(4)
    expect(rows[0].textContent).toContain('CVSS 3.1')
    expect(rows[0].textContent).toContain('8.1')
    expect(rows[0].textContent).toContain('from nvd')
    expect(rows[1].textContent).toContain('CVSS 4.0')
    expect(rows[1].textContent).toContain('9.2')
    expect(rows[1].textContent).toContain('from vendor')
    expect(rows[3].textContent).toContain('Attend')
    expect(screen.getByText('CVSS:3.1/AV:N/AC:H')).toBeTruthy()
  })

  it('shows the VEX statement as text, never as markup', () => {
    const { container } = render(<SourceDataSection data={mapFindingSourceData(api)!} />)
    expect(screen.getByText('Not affected')).toBeTruthy()
    expect(screen.getByText('vulnerable code not in execute path')).toBeTruthy()
    expect(container.querySelector('img')).toBeNull()
    expect(container.textContent).toContain('<img src=x onerror=alert(1)>')
    // Source fields are text too.
    expect(container.querySelector('b')).toBeNull()
  })

  it('links only http(s) advisories', () => {
    const { container } = render(<SourceDataSection data={mapFindingSourceData(api)!} />)
    const links = Array.from(container.querySelectorAll('a'))
    expect(links.map((a) => a.getAttribute('href'))).toEqual([
      'https://ubuntu.com/security/notices/USN-6859-1',
    ])
    expect(screen.getByText('EVIL-1').closest('a')).toBeNull()
  })

  it('shows the source record', () => {
    render(<SourceDataSection data={mapFindingSourceData(api)!} />)
    expect(screen.getByText('nessus 201194')).toBeTruthy()
    expect(screen.getByText('Confirmed')).toBeTruthy()
    expect(screen.getByText('No')).toBeTruthy() // credentialed: false is shown, not hidden
    expect(screen.getByText('41')).toBeTruthy()
    expect(screen.getByTestId('source-vuln-ids').textContent).toContain('USN-6859-1')
  })
})
