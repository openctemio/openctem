import { render, screen } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'

import type { PlatformScanningResponse } from '@/lib/api/platform-types'

import { PlatformScanningCard } from '../platform-scanning-card'

let scanning: { data?: PlatformScanningResponse; offered: boolean }
let proof: string | undefined
let admin = false

vi.mock('@/lib/api/platform-hooks', () => ({
  usePlatformScanning: () => scanning,
}))
vi.mock('@/lib/permissions', () => ({
  usePermissions: () => ({ isAdmin: () => admin }),
}))
vi.mock('@/features/scope', () => ({
  useScopeSettingsApi: () => ({ data: proof ? { active_proof: proof } : undefined }),
}))

const offered: PlatformScanningResponse = {
  offered: true,
  status: 'available',
  regions: [
    { name: 'eu', status: 'available' },
    { name: '', status: 'unavailable' },
  ],
  tools: ['httpx', 'nuclei'],
  your_jobs: { queued: 2, running: 1 },
  queue_limit_minutes: 60,
  egress: [
    { region: '', addresses: ['203.0.113.0/28'] },
    { region: 'eu', addresses: ['198.51.100.7', '2001:db8::7'] },
  ],
}

describe('PlatformScanningCard', () => {
  beforeEach(() => {
    scanning = { data: offered, offered: true }
    proof = undefined
    admin = false
  })

  it('renders nothing when the organization may not use shared sensors (no upsell)', () => {
    scanning = { data: { ...offered, offered: false }, offered: false }
    const { container } = render(<PlatformScanningCard />)
    expect(container).toBeEmptyDOMElement()
  })

  it('shows the service: state, regions, tools and the organization own jobs', () => {
    render(<PlatformScanningCard />)
    expect(screen.getByRole('heading', { name: 'Shared sensors' })).toBeInTheDocument()
    expect(screen.getAllByText('eu')).toHaveLength(2)
    expect(screen.getByText('Default region')).toBeInTheDocument()
    expect(screen.getByText('nuclei')).toBeInTheDocument()
    expect(screen.getByText('2 queued, 1 running')).toBeInTheDocument()
    expect(screen.getByText(/waits 60 minutes/)).toBeInTheDocument()
    // No proof line while the operator does not require it.
    expect(screen.queryByRole('link', { name: 'Verify a domain' })).not.toBeInTheDocument()
  })

  it('says when targets need a verified domain, with the way to verify one', () => {
    proof = 'platform_sensors'
    render(<PlatformScanningCard />)
    expect(screen.getByRole('link', { name: 'Verify a domain' })).toHaveAttribute(
      'href',
      '/scope?tab=proof'
    )
  })

  it('lists the egress addresses to allowlist, all regions first', () => {
    render(<PlatformScanningCard />)
    expect(screen.getByRole('heading', { name: 'Egress addresses' })).toBeInTheDocument()
    expect(screen.getByText('All regions')).toBeInTheDocument()
    expect(screen.getByText('203.0.113.0/28')).toBeInTheDocument()
    expect(screen.getByText('2001:db8::7')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Copy the addresses of eu' })).toBeInTheDocument()
  })

  it('shows no egress section when the administrator published none', () => {
    scanning = { data: { ...offered, egress: [] }, offered: true }
    render(<PlatformScanningCard />)
    expect(screen.queryByRole('heading', { name: 'Egress addresses' })).not.toBeInTheDocument()
  })

  it('links administrators to the organization opt-out, members not', () => {
    const { unmount } = render(<PlatformScanningCard />)
    expect(screen.queryByRole('link', { name: /Opt out/ })).not.toBeInTheDocument()
    unmount()
    admin = true
    render(<PlatformScanningCard />)
    expect(screen.getByRole('link', { name: /Opt out/ })).toHaveAttribute(
      'href',
      '/settings/authentication#tenant-shared-sensors-opt-out'
    )
  })
})
