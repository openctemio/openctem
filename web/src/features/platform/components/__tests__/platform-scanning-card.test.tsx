import { render, screen } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'

import type { PlatformScanningResponse } from '@/lib/api/platform-types'

import { PlatformScanningCard } from '../platform-scanning-card'

let scanning: { data?: PlatformScanningResponse; offered: boolean }
let proof: string | undefined

vi.mock('@/lib/api/platform-hooks', () => ({
  usePlatformScanning: () => scanning,
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
}

describe('PlatformScanningCard', () => {
  beforeEach(() => {
    scanning = { data: offered, offered: true }
    proof = undefined
  })

  it('renders nothing when the organization may not use platform scanning (no upsell)', () => {
    scanning = { data: { ...offered, offered: false }, offered: false }
    const { container } = render(<PlatformScanningCard />)
    expect(container).toBeEmptyDOMElement()
  })

  it('shows the service: state, regions, tools and the organization own jobs', () => {
    render(<PlatformScanningCard />)
    expect(screen.getByRole('heading', { name: 'Platform scanning' })).toBeInTheDocument()
    expect(screen.getByText('eu')).toBeInTheDocument()
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
})
