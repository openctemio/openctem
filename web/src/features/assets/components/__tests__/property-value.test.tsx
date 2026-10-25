import { describe, expect, it } from 'vitest'
import { fireEvent, render, screen, within } from '@testing-library/react'
import { PropertyValue, recordColumns, isIsoTimestamp } from '../property-value'
import { PropertiesSection } from '../asset-overview-sections'
import { humanizePropertyKey } from '@/features/asset-types/lib/property-schema'

const DNS = [
  { name: 'portal.example.com', ttl: 0, type: 'CNAME', value: 'portal-lb.edge.example.net' },
  { name: 'portal-lb.edge.example.net', ttl: 300, type: 'A', value: '203.0.113.21' },
]

describe('PropertyValue', () => {
  it('renders DNS records as a table: type, name, value, TTL', () => {
    render(<PropertyValue value={DNS} />)
    const table = screen.getByRole('table')
    const headers = within(table)
      .getAllByRole('columnheader')
      .map((h) => h.textContent)
    expect(headers).toEqual(['Type', 'Name', 'Value', 'TTL'])
    expect(within(table).getByText('203.0.113.21')).toBeInTheDocument()
    expect(within(table).getAllByRole('row')).toHaveLength(3)
    // Never the one-line JSON dump it used to be.
    expect(screen.queryByText(/"ttl"/)).not.toBeInTheDocument()
  })

  it('renders open ports with protocol, service, product and version', () => {
    render(
      <PropertyValue
        value={[
          { port: 22, protocol: 'tcp', service: 'ssh', product: 'OpenSSH', version: '9.6p1' },
          { port: 9200, protocol: 'tcp', service: 'elasticsearch' },
        ]}
      />
    )
    const headers = screen.getAllByRole('columnheader').map((h) => h.textContent)
    expect(headers).toEqual(['Port', 'Protocol', 'Service', 'Product', 'Version'])
    expect(screen.getByText('OpenSSH')).toBeInTheDocument()
    expect(screen.getByText('elasticsearch')).toBeInTheDocument()
  })

  it('caps a long table and shows every row on request', () => {
    const rows = Array.from({ length: 14 }, (_, i) => ({ type: 'A', value: `192.0.2.${i}` }))
    render(<PropertyValue value={rows} />)
    expect(screen.getAllByRole('row')).toHaveLength(11)
    fireEvent.click(screen.getByRole('button', { name: 'Show all 14' }))
    expect(screen.getAllByRole('row')).toHaveLength(15)
  })

  it('renders a flat object as labelled values', () => {
    render(<PropertyValue value={{ registrant_org: 'Example Corp', dnssec: 'unsigned' }} />)
    expect(screen.getByText('Registrant org')).toBeInTheDocument()
    expect(screen.getByText('DNSSEC')).toBeInTheDocument()
    expect(screen.getByText('Example Corp')).toBeInTheDocument()
  })

  it('pretty-prints a deep value in a collapsed JSON block', () => {
    const deep = [{ a: { b: { c: 1 } } }]
    render(<PropertyValue value={deep} />)
    const toggle = screen.getByRole('button', { name: /Show JSON/ })
    expect(toggle).toHaveAttribute('aria-expanded', 'false')
    fireEvent.click(toggle)
    const pre = document.querySelector('pre')
    expect(pre?.textContent).toBe(JSON.stringify(deep, null, 2))
    expect(pre?.textContent?.split('\n').length).toBeGreaterThan(3)
  })

  it('shows a timestamp as a local date, not the raw ISO string', () => {
    const iso = '2026-10-28T02:53:49.105Z'
    render(<PropertyValue value={iso} />)
    expect(screen.queryByText(iso)).not.toBeInTheDocument()
    expect(screen.getByText(new Date(iso).toLocaleString())).toBeInTheDocument()
  })

  it('renders scanner text as text, never as markup or a script link', () => {
    const evil = '<img src=x onerror=alert(1)>'
    const { container } = render(
      <>
        <PropertyValue value={[{ type: 'TXT', value: evil }]} />
        <PropertyValue value="javascript:alert(1)" format="url" />
      </>
    )
    expect(container.querySelector('img')).toBeNull()
    expect(screen.getByText(evil)).toBeInTheDocument()
    for (const a of Array.from(container.querySelectorAll('a'))) {
      expect(a.getAttribute('href') ?? '').not.toMatch(/^javascript:/i)
    }
  })

  it('a code value has a copy button', () => {
    render(<PropertyValue value="9F:86:D0:81" format="code" />)
    expect(screen.getByRole('button', { name: 'Copy value' })).toBeInTheDocument()
  })
})

describe('recordColumns / isIsoTimestamp', () => {
  it('only flat records make a table', () => {
    expect(recordColumns(DNS)).toEqual(['type', 'name', 'value', 'ttl'])
    expect(recordColumns([{ a: { b: 1 } }])).toBeNull()
    expect(recordColumns(['a', 'b'])).toBeNull()
    expect(recordColumns([])).toBeNull()
  })

  it('recognises ISO timestamps only', () => {
    expect(isIsoTimestamp('2026-10-28T02:53:49Z')).toBe(true)
    expect(isIsoTimestamp('2026-10-28')).toBe(false)
    expect(isIsoTimestamp('v2026-10-28T02:53')).toBe(false)
  })
})

describe('humanizePropertyKey', () => {
  it('keeps acronyms and splits camelCase', () => {
    expect(humanizePropertyKey('dns_record_count')).toBe('DNS record count')
    expect(humanizePropertyKey('vcenter_moref')).toBe('vCenter moref')
    expect(humanizePropertyKey('powerState')).toBe('Power state')
    expect(humanizePropertyKey('favorite_color')).toBe('Favorite color')
  })
})

describe('PropertiesSection', () => {
  it('shows DNS records as a table spanning the row', () => {
    render(<PropertiesSection type="subdomain" properties={{ dns_records: DNS }} />)
    expect(screen.getByText('DNS records')).toBeInTheDocument()
    expect(screen.getByRole('table')).toBeInTheDocument()
  })

  it('searches labels and values', () => {
    const properties = Object.fromEntries(
      Array.from({ length: 9 }, (_, i) => [`custom_key_${i}`, `value ${i}`])
    )
    render(<PropertiesSection properties={{ ...properties, waf: 'unknown' }} />)
    const search = screen.getByRole('searchbox', { name: /^Search properties/ })
    fireEvent.change(search, { target: { value: 'waf' } })
    expect(screen.getByText('WAF')).toBeInTheDocument()
    expect(screen.queryByText('Custom key 1')).not.toBeInTheDocument()
    fireEvent.change(search, { target: { value: 'nothing-matches' } })
    expect(screen.getByText('No property matches "nothing-matches".')).toBeInTheDocument()
  })
})
