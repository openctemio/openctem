/**
 * New Scan dynamic targets (RFC-068): a live preview of what each `*.x` or
 * inventory-mode CIDR holds now, the CIDR mode and the freshness options.
 */
import * as React from 'react'
import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { SWRConfig } from 'swr'
import { beforeEach, describe, expect, it, vi } from 'vitest'

const get = vi.fn()
const canRead = vi.hoisted(() => ({ value: true }))
vi.mock('@/lib/api/client', () => ({ get: (...a: unknown[]) => get(...a) }))
vi.mock('@/context/tenant-provider', () => ({ useTenant: () => ({ currentTenant: { id: 't1' } }) }))
vi.mock('@/lib/permissions', async (orig) => ({
  ...(await orig<typeof import('@/lib/permissions')>()),
  usePermissions: () => ({ can: () => canRead.value }),
}))

import type { ScanTargetOptions } from '@/lib/api/scan-types'
import { DynamicTargetsPanel } from '../new-scan/dynamic-targets-panel'

function Harness({
  targets,
  initial,
  onChange,
}: {
  targets: string[]
  initial?: ScanTargetOptions
  onChange?: (o: ScanTargetOptions) => void
}) {
  const [options, setOptions] = React.useState<ScanTargetOptions | undefined>(initial)
  return (
    <SWRConfig value={{ provider: () => new Map(), dedupingInterval: 0 }}>
      <DynamicTargetsPanel
        targets={targets}
        options={options}
        onChange={(o) => {
          setOptions(o)
          onChange?.(o)
        }}
        workflow
      />
    </SWRConfig>
  )
}

describe('DynamicTargetsPanel', () => {
  beforeEach(() => {
    get.mockReset()
    canRead.value = true
  })

  it('renders nothing without a wildcard or a range', () => {
    const { container } = render(<Harness targets={['example.com', '203.0.113.7']} />)
    expect(container).toBeEmptyDOMElement()
    expect(get).not.toHaveBeenCalled()
  })

  it('previews the known names of a wildcard and says it is re-resolved at every run', async () => {
    get.mockResolvedValue({
      data: [
        { name: 'new.example.com', last_seen: new Date().toISOString() },
        { name: 'api.example.com' },
      ],
      total: 42,
    })
    render(<Harness targets={['*.example.com']} />)
    const panel = screen.getByTestId('dynamic-targets')
    expect(within(panel).getByText(/Resolved again at the start of every run/)).toBeInTheDocument()
    expect(within(panel).getByText(/Discovery steps add what they find/)).toBeInTheDocument()
    await waitFor(() =>
      expect(within(panel).getByText(/example\.com and 42 known names now/)).toBeInTheDocument()
    )
    expect(within(panel).getByText(/Seen most recently: new\.example\.com/)).toBeInTheDocument()
    const url = new URL(String(get.mock.calls[0][0]), 'http://x')
    expect(url.searchParams.get('under')).toBe('example.com')
    expect(url.searchParams.get('statuses')).toBe('active')
  })

  it('says when a selector would be capped', async () => {
    get.mockResolvedValue({ data: [{ name: 'a.example.com' }], total: 9000 })
    render(<Harness targets={['*.example.com']} />)
    await waitFor(() =>
      expect(screen.getByText(/a run takes the 5,000 seen most recently/)).toBeInTheDocument()
    )
  })

  it('offers sweep or known hosts for a range, and previews the known hosts', async () => {
    const onChange = vi.fn()
    get.mockResolvedValue({ data: [{ name: '203.0.113.5' }], total: 1 })
    const user = userEvent.setup()
    render(<Harness targets={['203.0.113.0/24']} onChange={onChange} />)
    expect(screen.getByRole('radio', { name: 'Sweep the whole range' })).toBeChecked()
    expect(get).not.toHaveBeenCalled()

    await user.click(screen.getByRole('radio', { name: 'Only the hosts already in the inventory' }))
    expect(onChange).toHaveBeenLastCalledWith({ cidr_mode: 'inventory' })
    await waitFor(() =>
      expect(screen.getByText(/1 known host in this range now/)).toBeInTheDocument()
    )
    expect(new URL(String(get.mock.calls[0][0]), 'http://x').searchParams.get('in_cidr')).toBe(
      '203.0.113.0/24'
    )
  })

  it('sets the stale option and asks the preview for stale assets too', async () => {
    const onChange = vi.fn()
    get.mockResolvedValue({ data: [], total: 0 })
    const user = userEvent.setup()
    render(<Harness targets={['*.example.com']} onChange={onChange} />)
    await waitFor(() =>
      expect(screen.getByText(/No subdomains in your inventory yet/)).toBeInTheDocument()
    )
    await user.click(screen.getByRole('checkbox', { name: /Include assets not seen for a while/ }))
    expect(onChange).toHaveBeenLastCalledWith({ include_stale: true })
    await waitFor(() =>
      expect(
        get.mock.calls.some(
          (c) =>
            new URL(String(c[0]), 'http://x').searchParams.get('statuses') ===
            'active,stale,inactive'
        )
      ).toBe(true)
    )
  })

  it('reads nothing for someone who cannot read assets', () => {
    canRead.value = false
    render(<Harness targets={['*.example.com']} />)
    expect(get).not.toHaveBeenCalled()
    expect(screen.getByText(/shown to people who can read assets/)).toBeInTheDocument()
  })
})
