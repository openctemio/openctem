import { describe, expect, it, vi, beforeEach } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { toast } from 'sonner'

import { QuickScanDialog } from '../quick-scan-dialog'

// A wildcard typed into Quick Scan goes to the API as a scan target, the
// review shows what it expands to, and a refusal is worded in user terms.
const quickScan = vi.fn()
const previewPost = vi.fn()
vi.mock('@/lib/api/scan-workflow-hooks', () => ({
  useQuickScan: () => ({ trigger: quickScan }),
  invalidateScanRunsCache: vi.fn(),
  invalidateScanManagementStatsCache: vi.fn(),
}))
vi.mock('@/lib/api/scan-hooks', () => ({
  useSaveQuickScan: () => ({ trigger: vi.fn(), isMutating: false }),
  invalidateScanConfigsCache: vi.fn(),
}))
vi.mock('@/lib/api/client', async (orig) => ({
  ...(await orig<typeof import('@/lib/api/client')>()),
  post: (...args: unknown[]) => previewPost(...args),
}))
vi.mock('@/lib/api/tool-hooks', () => ({
  useTools: () => ({
    data: { items: [{ id: 't1', name: 'nuclei', display_name: 'Nuclei', is_active: true }] },
    isLoading: false,
  }),
  useToolAvailability: () => ({ data: undefined }),
}))
vi.mock('sonner', () => ({ toast: { success: vi.fn(), error: vi.fn() } }))
// Show the review content of the summary without the toggle.
vi.mock('../target-picker/selection-summary', () => ({
  SelectionSummary: ({ review }: { review?: React.ReactNode }) => <div>{review}</div>,
}))
vi.mock('@/context/tenant-provider', () => ({
  useTenant: () => ({ currentTenant: { id: 't1', name: 'ORG' } }),
}))

globalThis.ResizeObserver ??= class {
  observe() {}
  unobserve() {}
  disconnect() {}
}
Element.prototype.hasPointerCapture ??= () => false
Element.prototype.scrollIntoView ??= () => {}

async function fill(target: string) {
  await userEvent.type(screen.getByLabelText('Targets'), target)
  await userEvent.click(screen.getByLabelText('Scanner'))
  await userEvent.click(await screen.findByRole('option', { name: 'Nuclei' }))
}

describe('QuickScanDialog wildcard targets', () => {
  beforeEach(() => {
    quickScan.mockReset()
    previewPost.mockReset()
    previewPost.mockResolvedValue({ targets: [] })
    vi.mocked(toast.error).mockReset()
  })

  it('sends the wildcard as a target, with no scanner settings', async () => {
    quickScan.mockResolvedValue({
      scan_run_id: 'r',
      scan_id: 's',
      status: 'pending',
      target_count: 1,
    })
    render(<QuickScanDialog open onOpenChange={vi.fn()} />)
    await fill('*.pti.com.vn')
    await userEvent.click(screen.getByRole('button', { name: /Start Scan/ }))
    expect(quickScan).toHaveBeenCalledWith({ targets: ['*.pti.com.vn'], scanner_name: 'nuclei' })
  })

  it('words a refused wildcard in user terms, not the server text', async () => {
    quickScan.mockRejectedValue(
      Object.assign(new Error('Target "*.x" in the scanner settings is a pattern'), {
        code: 'WILDCARD_TARGET',
        statusCode: 400,
      })
    )
    render(<QuickScanDialog open onOpenChange={vi.fn()} />)
    await fill('*.example.com')
    await userEvent.click(screen.getByRole('button', { name: /Start Scan/ }))
    await vi.waitFor(() => expect(toast.error).toHaveBeenCalled())
    const text = String(vi.mocked(toast.error).mock.calls[0][0])
    expect(text).toContain('*.example.com')
    expect(text).not.toContain('scanner settings')
  })

  it('shows the expansion: known, scanned, left out with reason, examples', async () => {
    previewPost.mockResolvedValue({
      targets: [
        {
          target: '*.pti.com.vn',
          kind: 'wildcard',
          known: 12,
          in_scope: 9,
          skipped: [{ reason: 'excluded', count: 3 }],
          excluded_rules: ['vpn.pti.com.vn'],
          sample: ['pti.com.vn', 'api.pti.com.vn'],
        },
      ],
    })
    render(<QuickScanDialog open onOpenChange={vi.fn()} />)
    await fill('*.pti.com.vn')
    expect(await screen.findByText('12 known assets match')).toBeInTheDocument()
    expect(screen.getByText('9 will be scanned')).toBeInTheDocument()
    expect(screen.getByText('3 left out by exclusions or the deny list')).toBeInTheDocument()
    expect(screen.getByText('Examples: pti.com.vn, api.pti.com.vn')).toBeInTheDocument()
    expect(previewPost).toHaveBeenCalledWith(
      expect.stringContaining('/quick/preview'),
      expect.objectContaining({ targets: ['*.pti.com.vn'], scanner_name: 'nuclei' })
    )
  })

  it('with no known names offers discovery on the apex instead of failing', async () => {
    quickScan.mockResolvedValue({
      scan_run_id: 'r',
      scan_id: 's',
      status: 'pending',
      target_count: 1,
    })
    previewPost.mockResolvedValue({
      targets: [
        {
          target: '*.new.pti.com.vn',
          kind: 'wildcard',
          known: 0,
          in_scope: 1,
          discovery: { tool: 'subfinder', root: 'new.pti.com.vn' },
        },
      ],
    })
    render(<QuickScanDialog open onOpenChange={vi.fn()} />)
    await fill('*.new.pti.com.vn')
    await userEvent.click(
      await screen.findByRole(
        'button',
        { name: /Run discovery on new.pti.com.vn/ },
        { timeout: 3000 }
      )
    )
    expect(quickScan).toHaveBeenCalledWith({
      targets: ['new.pti.com.vn'],
      scanner_name: 'subfinder',
    })
  })
})
