import { describe, expect, it, vi, beforeEach } from 'vitest'
import { useState } from 'react'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

const page = Array.from({ length: 5 }, (_, i) => ({
  id: `a${i}`,
  name: `host-${i}.example.com`,
  type: 'domain',
  criticality: 'high',
}))
const useAssetsCalls: Record<string, unknown>[] = []
vi.mock('@/features/assets', () => ({
  useAssets: (f: Record<string, unknown>) => {
    useAssetsCalls.push(f)
    return {
      assets: f.skip ? [] : page,
      total: 1200,
      totalPages: 48,
      isLoading: false,
      isError: false,
      error: null,
    }
  },
  ASSET_TYPE_LABELS: { domain: 'Domain' },
  ASSET_TYPE_COLORS: { domain: { bg: 'bg-x', text: 'text-x' } },
}))
const fetchAll = vi.fn()
vi.mock('@/features/assets/hooks/use-assets', () => ({
  fetchAllAssets: (...a: unknown[]) => fetchAll(...a),
}))
const toastWarning = vi.fn()
vi.mock('sonner', () => ({ toast: { warning: (m: string) => toastWarning(m), error: vi.fn() } }))

import { AssetSource } from '../asset-source'

Element.prototype.hasPointerCapture ??= () => false
Element.prototype.scrollIntoView ??= () => {}

function Harness() {
  const [selected, setSelected] = useState<Record<string, string>>({})
  return (
    <>
      <AssetSource
        selected={selected}
        onChange={(assets, picked) =>
          setSelected((prev) => {
            const next = { ...prev }
            for (const a of assets) {
              if (picked) next[a.id] = a.name
              else delete next[a.id]
            }
            return next
          })
        }
      />
      <output data-testid="picked">{Object.keys(selected).sort().join(',')}</output>
    </>
  )
}

const picked = () => screen.getByTestId('picked').textContent

describe('AssetSource', () => {
  beforeEach(() => {
    useAssetsCalls.length = 0
    fetchAll.mockReset()
    toastWarning.mockReset()
  })

  it('pages on the server and picks single rows', async () => {
    render(<Harness />)
    expect(useAssetsCalls.at(-1)).toMatchObject({ page: 1, pageSize: 25 })
    await userEvent.click(screen.getByRole('checkbox', { name: 'host-1.example.com' }))
    expect(picked()).toBe('a1')
  })

  it('picks a range with shift-click', async () => {
    render(<Harness />)
    const user = userEvent.setup()
    await user.click(screen.getByRole('checkbox', { name: 'host-0.example.com' }))
    await user.keyboard('{Shift>}')
    await user.click(screen.getByRole('checkbox', { name: 'host-3.example.com' }))
    await user.keyboard('{/Shift}')
    expect(picked()).toBe('a0,a1,a2,a3')
  })

  it('picks the page, then every match up to the direct-target limit, and says so', async () => {
    fetchAll.mockResolvedValue(
      Array.from({ length: 1200 }, (_, i) => ({ id: `m${i}`, name: `m${i}.example.com` }))
    )
    render(<Harness />)
    await userEvent.click(screen.getByRole('checkbox', { name: 'Select this page' }))
    expect(picked()?.split(',')).toHaveLength(5)
    await userEvent.click(screen.getByRole('button', { name: /Select all 1,200 matching/ }))
    await waitFor(() => expect(picked()?.split(',').length).toBe(1005))
    expect(toastWarning).toHaveBeenCalledWith(expect.stringMatching(/first 1,000 of 1,200/))
  })

  it('sends the filters to the server and shows only the selection on demand', async () => {
    render(<Harness />)
    await userEvent.type(screen.getByLabelText('Search assets'), 'api')
    await waitFor(() => expect(useAssetsCalls.at(-1)).toMatchObject({ search: 'api', page: 1 }))
    await userEvent.click(screen.getByRole('checkbox', { name: 'host-2.example.com' }))
    await userEvent.click(screen.getByRole('switch'))
    expect(useAssetsCalls.at(-1)).toMatchObject({ skip: true })
    expect(screen.getByRole('checkbox', { name: 'host-2.example.com' })).toBeChecked()
    expect(screen.queryByRole('checkbox', { name: 'host-0.example.com' })).toBeNull()
  })
})
