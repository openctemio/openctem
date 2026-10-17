import { render, screen, within } from '@testing-library/react'
import { SWRConfig } from 'swr'
import { describe, expect, it, vi } from 'vitest'
import type { ReactNode } from 'react'

import { TooltipProvider } from '@/components/ui/tooltip'

import type { Asset } from '../../../types'
import { AssetTechnologiesSection } from '../asset-technologies-section'
import { AssetTechnologiesTab } from '../asset-technologies-tab'
import { TechnologiesByCategory, groupByCategory } from '../technologies-by-category'

const api = vi.hoisted(() => ({ get: vi.fn() }))
vi.mock('@/lib/api/client', () => api)
vi.mock('@/lib/permissions', async (orig) => ({
  ...(await orig<typeof import('@/lib/permissions')>()),
  usePermissions: () => ({ can: () => true }),
}))

const wrap = (ui: ReactNode) =>
  render(
    <SWRConfig value={{ provider: () => new Map(), dedupingInterval: 0 }}>
      <TooltipProvider>{ui}</TooltipProvider>
    </SWRConfig>
  )

const TECHS = [
  { name: 'Vercel', category: 'hosting' as const },
  { name: 'nginx', version: '1.25.3', category: 'web_server' as const },
  { name: 'HSTS', category: 'security_header' as const },
  { name: 'Next.js', version: '13.4.1', category: 'framework' as const },
  { name: 'Apache', category: 'web_server' as const },
]

describe('technologies by category', () => {
  it('groups in display order and sorts names', () => {
    const groups = groupByCategory(TECHS)
    expect(groups.map((g) => g.category)).toEqual([
      'web_server',
      'framework',
      'hosting',
      'security_header',
    ])
    expect(groups[0].items.map((i) => i.name)).toEqual(['Apache', 'nginx'])
  })

  it('renders one labelled row per category with versioned chips', () => {
    wrap(<TechnologiesByCategory technologies={TECHS} />)
    expect(screen.getByText('Web servers')).toBeInTheDocument()
    expect(screen.getByText('Hosting and PaaS')).toBeInTheDocument()
    expect(screen.getByText('Security headers')).toBeInTheDocument()
    expect(screen.getByText('nginx 1.25.3')).toBeInTheDocument()
    expect(screen.getByText('Vercel')).toBeInTheDocument()
  })

  it('renders scanner text as text', () => {
    const { container } = wrap(
      <TechnologiesByCategory
        technologies={[{ name: '<img src=x onerror=alert(1)>', category: 'other' }]}
      />
    )
    expect(container.querySelector('img')).toBeNull()
    expect(screen.getByText('<img src=x onerror=alert(1)>')).toBeInTheDocument()
  })
})

describe('AssetTechnologiesSection', () => {
  it('is hidden when nothing was detected and fetches nothing', () => {
    api.get.mockClear()
    const { container } = wrap(<AssetTechnologiesSection asset={{ id: 'a1' } as Asset} />)
    expect(container).toBeEmptyDOMElement()
    expect(api.get).not.toHaveBeenCalled()
  })

  it('shows the embedded technologies with a count', async () => {
    api.get.mockResolvedValue({ data: [] })
    wrap(<AssetTechnologiesSection asset={{ id: 'a1', technologies: TECHS } as Asset} />)
    const section = screen.getByRole('region', { name: /Technologies/ })
    expect(within(section).getByText('5')).toBeInTheDocument()
    expect(within(section).getByText('Next.js 13.4.1')).toBeInTheDocument()
  })
})

describe('AssetTechnologiesTab', () => {
  it('lists every technology with confidence, source and sightings', async () => {
    api.get.mockResolvedValue({
      data: [
        {
          name: 'nginx',
          version: '1.25.3',
          category: 'web_server',
          kind: 'software',
          confidence: 80,
          source: 'httpx',
          first_seen_at: '2026-10-01T00:00:00Z',
          last_seen_at: '2026-10-15T00:00:00Z',
        },
      ],
    })
    wrap(<AssetTechnologiesTab assetId="a1" />)
    expect(await screen.findByText('nginx')).toBeInTheDocument()
    expect(api.get).toHaveBeenCalledWith('/api/v1/assets/a1/technologies')
    expect(screen.getByText('Confidence 80 · Source: httpx')).toBeInTheDocument()
    expect(screen.getByRole('region', { name: 'Web servers' })).toBeInTheDocument()
  })

  it('explains what technologies are when there are none', async () => {
    api.get.mockResolvedValue({ data: [] })
    wrap(<AssetTechnologiesTab assetId="a1" />)
    expect(await screen.findByText('No technologies detected')).toBeInTheDocument()
  })
})
