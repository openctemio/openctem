import { beforeEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen, within } from '@testing-library/react'
import { KeyFactsSection, factValue, hasKeyFacts } from '../key-facts'
import { PropertiesSection } from '../asset-overview-sections'
import { technologies } from '../../lib/service-facts'
import type { Asset } from '../../types/asset.types'

let servedCertificate: Asset | null = null
vi.mock('../../hooks/use-served-certificate', () => ({
  useServedCertificate: () => servedCertificate,
}))

function asset(type: string, metadata: Record<string, unknown>, subType?: string): Asset {
  return {
    id: 'a1',
    type,
    subType,
    name: 'x',
    criticality: 'medium',
    status: 'active',
    scope: 'external',
    exposure: 'public',
    riskScore: 0,
    findingCount: 0,
    metadata,
    firstSeen: '',
    lastSeen: '',
    createdAt: '',
    updatedAt: '',
  } as unknown as Asset
}

const SUBDOMAIN_BASE = asset('subdomain', {
  ip_addresses: ['203.0.113.21', '203.0.113.22', '203.0.113.23'],
  cname_target: 'lb.edge.example.net',
  asn: 'AS64500',
  asn_org: 'Example Hosting Ltd',
  has_tls: true,
  tls_version: 'TLS 1.2',
  dns_records: [
    { name: 'portal.example.com', ttl: 300, type: 'CNAME', value: 'lb.edge.example.net' },
    { name: 'lb.edge.example.net', ttl: 300, type: 'A', value: '203.0.113.21' },
  ],
  dns_record_count: 2,
})
const SUBDOMAIN = {
  ...SUBDOMAIN_BASE,
  technologies: [
    { name: 'nginx', version: '1.24.0', category: 'web_server' },
    { name: 'React', category: 'js_library' },
  ],
} as Asset

describe('KeyFactsSection served certificate', () => {
  const SERVICE = asset(
    'service',
    { port: 443, protocol: 'https', scheme: 'https', tls_fingerprint: 'ab:cd' },
    'http'
  )
  const CERT = asset('certificate', {
    subject_cn: 'shop.example.com',
    sans: ['shop.example.com'],
    issuer_org: 'Example CA',
    not_after: new Date(Date.now() + 200 * 24 * 60 * 60 * 1000).toISOString(),
  })

  beforeEach(() => {
    servedCertificate = null
  })

  it('reads the linked certificate instead of saying it was not collected', () => {
    servedCertificate = CERT
    render(<KeyFactsSection asset={SERVICE} />)
    expect(screen.queryByText(/Not collected yet.*TLS/)).not.toBeInTheDocument()
    expect(screen.getAllByText(/Example CA/).length).toBeGreaterThan(0)
  })

  it('still says so when no certificate is linked', () => {
    const bare = asset('service', { port: 8443 }, 'http')
    render(<KeyFactsSection asset={bare} />)
    expect(screen.getByText(/Not collected yet/)).toHaveTextContent(/TLS/)
  })
})

describe('KeyFactsSection', () => {
  it('a subdomain: resolves to (every address), CNAME, hosting, TLS, stack, DNS table', () => {
    render(<KeyFactsSection asset={SUBDOMAIN} />)
    expect(screen.getByRole('heading', { name: 'Key facts' })).toBeInTheDocument()
    expect(screen.getByText('Resolves to')).toBeInTheDocument()
    for (const ip of ['203.0.113.21', '203.0.113.22', '203.0.113.23']) {
      expect(screen.getAllByText(ip).length).toBeGreaterThan(0)
    }
    expect(screen.getByText('lb.edge.example.net', { selector: 'dd' })).toBeInTheDocument()
    expect(screen.getByText('AS64500, Example Hosting Ltd')).toBeInTheDocument()
    expect(screen.getByText('TLS 1.2')).toBeInTheDocument()
    // Technologies have their own section, not a key fact row.
    expect(screen.queryByText('nginx')).not.toBeInTheDocument()
    expect(screen.queryByText('1.24.0')).not.toBeInTheDocument()
    const table = screen.getByRole('table')
    expect(within(table).getAllByRole('row')).toHaveLength(3)
    // No "+N" anywhere: every value is listed.
    expect(screen.queryByText(/^\+\d+$/)).not.toBeInTheDocument()
    // A derived leftover is not a key fact.
    expect(screen.queryByText('DNS record count')).not.toBeInTheDocument()
  })

  it('a certificate: subject, every SAN, issuer, validity and key', () => {
    const { container } = render(
      <KeyFactsSection
        asset={asset('certificate', {
          subject_cn: 'portal.example.com',
          sans: ['portal.example.com', 'api.portal.example.com', 'm.portal.example.com'],
          issuer_cn: 'Example CA',
          issuer_org: 'Example Trust',
          not_after: '2026-10-28T02:53:49Z',
          key_algorithm: 'RSA',
          key_size: 2048,
        })}
      />
    )
    expect(screen.getByText('Subject CN')).toBeInTheDocument()
    expect(container.textContent).toContain('m.portal.example.com')
    expect(screen.getByText('Example CA, Example Trust')).toBeInTheDocument()
    expect(screen.getByText('Valid until')).toBeInTheDocument()
    expect(screen.getByText('RSA 2048')).toBeInTheDocument()
  })

  it('an IP: network owner, location and the open-port table', () => {
    render(
      <KeyFactsSection
        asset={asset('ip_address', {
          asn: 'AS64500',
          asn_org: 'Example Hosting Ltd',
          city: 'Hanoi',
          country: 'VN',
          ports: [{ port: 22, protocol: 'tcp', service: 'ssh', product: 'OpenSSH' }],
        })}
      />
    )
    expect(screen.getByText('Network owner')).toBeInTheDocument()
    expect(screen.getByText('Hanoi, VN')).toBeInTheDocument()
    expect(within(screen.getByRole('table')).getByText('OpenSSH')).toBeInTheDocument()
  })

  it('a host: operating system and hardware in one line each', () => {
    render(
      <KeyFactsSection
        asset={asset('host', {
          os_name: 'Ubuntu',
          os_version: '22.04',
          cpu_count: 8,
          memory_gb: 32,
          architecture: 'x86_64',
        })}
      />
    )
    expect(screen.getByText('Ubuntu 22.04')).toBeInTheDocument()
    expect(screen.getByText('8 CPU, 32 GB, x86_64')).toBeInTheDocument()
  })

  it('renders nothing for an asset with no key fact and nothing missing', () => {
    const { container } = render(<KeyFactsSection asset={asset('repository', {})} />)
    expect(container).toBeEmptyDOMElement()
    expect(hasKeyFacts(asset('repository', {}))).toBe(false)
    expect(hasKeyFacts(SUBDOMAIN)).toBe(true)
  })

  it('reads a synonym an older row still holds', () => {
    expect(factValue({ web_server: 'nginx' }, 'server')).toBe('nginx')
  })
})

describe('technologies()', () => {
  it('reads the technologies the asset API embeds', () => {
    const got = technologies({
      technologies: [
        { name: 'nginx', version: '1.24.0', category: 'web_server' },
        { name: 'React', category: 'js_library' },
      ],
    })
    expect(got).toEqual([{ name: 'nginx', version: '1.24.0' }, { name: 'React' }])
    expect(technologies({ technologies: [] })).toBeNull()
  })
})

describe('All properties under the key facts', () => {
  it('is folded until opened', () => {
    render(<PropertiesSection properties={{ registrar: 'Example Registrar' }} all />)
    expect(screen.getByRole('heading', { name: /All properties/ })).toBeInTheDocument()
    expect(screen.queryByText('Example Registrar')).not.toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'Show' }))
    expect(screen.getByText('Example Registrar')).toBeInTheDocument()
  })
})
