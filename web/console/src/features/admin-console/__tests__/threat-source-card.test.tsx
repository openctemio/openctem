import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import { saveThreatSource, useThreatSource } from '../api/use-platform-settings'
import { ThreatSourceCard } from '../components/threat-source-card'
import type { ThreatSourceSettings } from '../types'

vi.mock('../api/use-platform-settings', () => ({
  useThreatSource: vi.fn(),
  saveThreatSource: vi.fn(),
}))
vi.mock('sonner', () => ({ toast: { success: vi.fn(), error: vi.fn() } }))

const SEEDED: ThreatSourceSettings = {
  source: 'direct',
  direct_fetch: 'auto',
  stored: false,
  version: 0,
  feeds: [
    {
      source: 'kev',
      bundle_fetched_at: new Date().toISOString(),
      bundle_fresh: true,
      delivered_via: 'direct',
    },
    { source: 'epss', bundle_fresh: false },
  ],
}

function seed(data: ThreatSourceSettings) {
  vi.mocked(useThreatSource).mockReturnValue({
    data,
    error: undefined,
    isLoading: false,
    mutate: vi.fn(),
  } as unknown as ReturnType<typeof useThreatSource>)
}

describe('ThreatSourceCard', () => {
  beforeEach(() => vi.clearAllMocks())

  it('shows the defaults and how the release is doing per feed', () => {
    seed(SEEDED)
    render(<ThreatSourceCard canEdit />)
    expect(screen.getByRole('switch', { name: /use the signed release/i })).not.toBeChecked()
    expect(screen.getByRole('switch', { name: /call cisa and first/i })).toBeChecked()
    expect(screen.getByText(/no release has carried this feed yet/i)).toBeInTheDocument()
    expect(screen.getByText(/release copy read/i)).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Save' })).toBeDisabled()
  })

  it('saves the switched values with the version read', async () => {
    seed({ ...SEEDED, version: 3, stored: true })
    vi.mocked(saveThreatSource).mockResolvedValue(SEEDED)
    render(<ThreatSourceCard canEdit />)
    await userEvent.click(screen.getByRole('switch', { name: /use the signed release/i }))
    await userEvent.click(screen.getByRole('switch', { name: /call cisa and first/i }))
    await userEvent.click(screen.getByRole('button', { name: 'Save' }))
    await waitFor(() =>
      expect(saveThreatSource).toHaveBeenCalledWith({
        source: 'bundle',
        direct_fetch: 'off',
        version: 3,
      })
    )
  })

  it('a read-only viewer cannot change or save', () => {
    seed(SEEDED)
    render(<ThreatSourceCard canEdit={false} />)
    expect(screen.getByRole('switch', { name: /use the signed release/i })).toBeDisabled()
    expect(screen.queryByRole('button', { name: 'Save' })).not.toBeInTheDocument()
  })
})
