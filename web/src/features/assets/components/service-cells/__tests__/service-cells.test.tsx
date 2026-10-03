import { describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import type { Asset } from '../../../types'
import { tlsFacts } from '../../../lib/service-facts'
import {
  bareService,
  ctisCertificate,
  sensorHttpService,
  sensorIpWithPorts,
} from '../../../lib/__fixtures__/ingest-shaped-assets'
import {
  HttpStatusChip,
  IssuesChip,
  LabelChips,
  OverflowChips,
  SurfaceFacts,
  TechChips,
  TlsSummary,
  UNRESOLVED_FINDING_STATUSES,
  cellsForType,
  httpStatusTone,
  labelError,
  safeExternalHref,
  MAX_TAGS_PER_ASSET,
} from '..'

describe('HttpStatusChip', () => {
  it('colours by the class of the final status', () => {
    expect(httpStatusTone(200)).toBe('success')
    expect(httpStatusTone(302)).toBe('info')
    expect(httpStatusTone(401)).toBe('warning')
    expect(httpStatusTone(403)).toBe('warning')
    expect(httpStatusTone(404)).toBe('destructive')
    expect(httpStatusTone(503)).toBe('destructive')
  })

  it('shows the redirect chain then the final status', () => {
    render(<HttpStatusChip status={200} chain={[301]} />)
    expect(screen.getByText('301, 200')).toBeInTheDocument()
    expect(screen.getByText('OK')).toBeInTheDocument()
    expect(screen.getByTitle('Redirect chain: 301 → 200')).toHaveAttribute('data-tone', 'success')
  })

  it('says "Status unknown" (dashed), never a default 200', () => {
    render(<HttpStatusChip status={null} />)
    const chip = screen.getByText('Status unknown')
    expect(chip).toHaveAttribute('data-tone', 'unknown')
    expect(screen.queryByText('200')).toBeNull()
  })
})

describe('IssuesChip', () => {
  it("links to the asset's unresolved findings", () => {
    render(<IssuesChip assetId="a/1" count={4} />)
    const link = screen.getByRole('link', { name: /4 issues found/ })
    const href = new URL(link.getAttribute('href') ?? '', 'http://x')
    expect(href.pathname).toBe('/findings')
    expect(href.searchParams.get('assetId')).toBe('a/1')
    expect(href.searchParams.get('status')?.split(',')).toEqual([...UNRESOLVED_FINDING_STATUSES])
    expect(href.searchParams.get('status')).not.toContain('resolved,')
  })

  it('renders nothing at zero', () => {
    const { container } = render(<IssuesChip assetId="a" count={0} />)
    expect(container).toBeEmptyDOMElement()
  })
})

describe('OverflowChips', () => {
  it('shows the first value and "+N" naming the rest', () => {
    render(<OverflowChips label="IP" values={['192.0.2.1', '192.0.2.2', '192.0.2.3']} />)
    expect(screen.getByText('192.0.2.1')).toBeInTheDocument()
    expect(
      screen.getByRole('button', { name: '2 more IP: 192.0.2.2, 192.0.2.3' })
    ).toHaveTextContent('+2')
  })

  it('renders nothing for no values', () => {
    const { container } = render(<OverflowChips label="CNAME" values={[]} />)
    expect(container).toBeEmptyDOMElement()
  })
})

describe('TechChips', () => {
  it('shows name and version', () => {
    render(<TechChips technologies={[{ name: 'jQuery', version: '3.3.1' }, { name: 'React' }]} />)
    expect(screen.getByTitle('jQuery 3.3.1')).toBeInTheDocument()
    expect(screen.getByTitle('React')).toBeInTheDocument()
  })

  it('has two explicit empty states', () => {
    const { rerender } = render(<TechChips technologies={[]} />)
    expect(screen.getByText('No technologies')).toHaveAttribute('data-tone', 'unknown')
    rerender(<TechChips technologies={null} />)
    expect(screen.getByText('Not collected')).toHaveAttribute('data-tone', 'unknown')
  })
})

describe('TlsSummary', () => {
  const NOW = Date.now()
  const DAY = 24 * 60 * 60 * 1000

  it('shows expiry, issuer and SAN of a certificate', () => {
    const asset = ctisCertificate(new Date(NOW - 133 * DAY).toISOString())
    render(<TlsSummary facts={tlsFacts(asset, NOW)} />)
    expect(screen.getByText('Expired 133 days ago')).toHaveAttribute('data-tone', 'destructive')
    expect(screen.getByText("Let's Encrypt")).toBeInTheDocument()
    expect(screen.getByText('*.example.com')).toBeInTheDocument()
  })

  it('says "Expires in N days" inside the window and "Valid" after', () => {
    const { rerender } = render(
      <TlsSummary facts={tlsFacts(ctisCertificate(new Date(NOW + 18 * DAY).toISOString()), NOW)} />
    )
    expect(screen.getByText('Expires in 18 days')).toHaveAttribute('data-tone', 'warning')
    rerender(
      <TlsSummary facts={tlsFacts(ctisCertificate(new Date(NOW + 212 * DAY).toISOString()), NOW)} />
    )
    expect(screen.getByText('Valid · 212 days left')).toHaveAttribute('data-tone', 'success')
  })

  it('keeps "No TLS", "TLS, certificate not collected" and "Not collected" apart', () => {
    const { rerender } = render(<TlsSummary facts={{ kind: 'none' }} />)
    expect(screen.getByText('No TLS')).toBeInTheDocument()
    rerender(<TlsSummary facts={{ kind: 'tls' }} />)
    expect(screen.getByText('Certificate not collected')).toBeInTheDocument()
    rerender(<TlsSummary facts={{ kind: 'not_collected' }} />)
    expect(screen.getByText('Not collected')).toHaveAttribute('data-tone', 'unknown')
  })
})

describe('LabelChips', () => {
  it('shows labels with "+N" and no add button without write access', () => {
    render(<LabelChips labels={['prod', 'online-store', 'pci']} />)
    expect(screen.getByText('prod')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: '1 more labels: pci' })).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /add label/i })).toBeNull()
  })

  it('adds a label through the popover', async () => {
    const onSave = vi.fn().mockResolvedValue(undefined)
    render(<LabelChips labels={['prod']} onSave={onSave} />)
    fireEvent.click(screen.getByRole('button', { name: /add label/i }))
    fireEvent.change(await screen.findByLabelText('Add label'), {
      target: { value: '  marketing-site ' },
    })
    fireEvent.click(screen.getByRole('button', { name: 'Add' }))
    await waitFor(() => expect(onSave).toHaveBeenCalledWith(['prod', 'marketing-site']))
  })

  it('refuses a duplicate, an over-long label and a 51st label', () => {
    expect(labelError(['prod'], 'prod')).toMatch(/already/)
    expect(labelError([], 'x'.repeat(51))).toMatch(/at most 50 characters/)
    const full = Array.from({ length: MAX_TAGS_PER_ASSET }, (_, i) => `t${i}`)
    expect(labelError(full, 'one-more')).toMatch(/at most 50 labels/)
    expect(labelError([], ' ')).toBe('Enter a label')
    expect(labelError(full.slice(1), 'ok')).toBeNull()
  })
})

describe('scanner text is text', () => {
  it('renders HTML from a scanner as literal text', () => {
    const evil = '<img src=x onerror="alert(1)">'
    const { container } = render(
      <>
        <TechChips technologies={[{ name: evil }]} />
        <OverflowChips label="CNAME" values={[evil]} />
        <LabelChips labels={[evil]} />
      </>
    )
    expect(container.querySelector('img')).toBeNull()
    expect(screen.getAllByText(evil).length).toBeGreaterThan(0)
  })

  it('only links absolute http(s) URLs without credentials', () => {
    expect(safeExternalHref('https://www.example.net/en/')).toBe('https://www.example.net/en/')
    expect(safeExternalHref('javascript:alert(1)')).toBeNull()
    expect(safeExternalHref('data:text/html,<b>x</b>')).toBeNull()
    expect(safeExternalHref('//evil.example')).toBeNull()
    expect(safeExternalHref('https://user:pass@example.com')).toBeNull()
    expect(safeExternalHref('https://exa mple.com')).toBeNull()
    expect(safeExternalHref(42)).toBeNull()
  })
})

describe('cellsForType', () => {
  it('gives service cells to the external-surface types only', () => {
    for (const [type, sub] of [
      ['service', 'http'],
      ['service', 'open_port'],
      ['service', 'discovered_url'],
      ['service', undefined],
      ['application', 'website'],
      ['application', 'web_application'],
      ['application', 'api'],
      ['domain', undefined],
      ['subdomain', undefined],
      ['ip_address', undefined],
      ['certificate', undefined],
      ['website', undefined],
      ['http_service', undefined],
      ['open_port', undefined],
      ['discovered_url', undefined],
      ['api', undefined],
    ] as const) {
      expect(cellsForType(type, sub), `${type}:${sub}`).not.toBeNull()
    }
    for (const type of [
      'repository',
      'cloud_account',
      'kubernetes',
      'identity',
      'database',
      'host',
      'storage',
    ]) {
      expect(cellsForType(type), type).toBeNull()
    }
    expect(cellsForType('application')).toBeNull()
  })

  it('SurfaceFacts renders an http service and nothing for a repository', () => {
    const { container, rerender } = render(<SurfaceFacts asset={sensorHttpService} />)
    expect(screen.getByText('200')).toBeInTheDocument()
    expect(screen.getByTitle('Nginx 1.25.3')).toBeInTheDocument()
    expect(screen.getByText('443/https')).toBeInTheDocument()
    rerender(<SurfaceFacts asset={{ ...bareService, type: 'repository' } as Asset} />)
    expect(container).toBeEmptyDOMElement()
  })

  it('SurfaceFacts shows open ports for an IP and unknowns for a bare service', () => {
    const { rerender } = render(<SurfaceFacts asset={sensorIpWithPorts} />)
    expect(screen.getByText('22/tcp')).toBeInTheDocument()
    rerender(<SurfaceFacts asset={bareService} />)
    expect(screen.getByText('Port unknown')).toBeInTheDocument()
    expect(screen.getByText('Status unknown')).toBeInTheDocument()
  })
})
