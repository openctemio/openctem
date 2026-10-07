import { describe, expect, it, vi, beforeEach } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import { QuickScanDialog, defaultSaveName } from '../quick-scan-dialog'

// D10: a quick scan runs without leaving a configuration behind; "Save as
// scan" turns it into one.
const quickScan = vi.fn()
const saveQuickScan = vi.fn()
const saveHookIds: Array<string | null> = []
vi.mock('@/lib/api/pipeline-hooks', () => ({
  useQuickScan: () => ({ trigger: quickScan }),
  invalidatePipelineRunsCache: vi.fn(),
  invalidateScanManagementStatsCache: vi.fn(),
}))
vi.mock('@/lib/api/scan-hooks', () => ({
  useSaveQuickScan: (id: string | null) => {
    saveHookIds.push(id)
    return { trigger: saveQuickScan, isMutating: false }
  },
  invalidateScanConfigsCache: vi.fn(),
}))
vi.mock('@/lib/api/tool-hooks', () => ({
  useTools: () => ({
    data: { items: [{ id: 't1', name: 'nuclei', display_name: 'Nuclei', is_active: true }] },
    isLoading: false,
  }),
  // Availability unknown: nothing is disabled.
  useToolAvailability: () => ({ data: undefined }),
}))
vi.mock('sonner', () => ({ toast: { success: vi.fn(), error: vi.fn() } }))
// The live scope preview has its own tests (new-scan/__tests__/scope-preview).
vi.mock('../new-scan/scope-preview', () => ({ ScopePreview: () => null }))
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

describe('QuickScanDialog', () => {
  beforeEach(() => {
    quickScan.mockReset()
    saveQuickScan.mockReset()
    saveHookIds.length = 0
  })

  it('needs targets and a scanner chosen from the registry, then starts without saving', async () => {
    quickScan.mockResolvedValue({
      scan_run_id: 'r1',
      scan_id: 's1',
      status: 'pending',
      target_count: 2,
    })
    render(<QuickScanDialog open onOpenChange={vi.fn()} />)
    const start = screen.getByRole('button', { name: /Start Scan/ })
    expect(start).toBeDisabled()

    await userEvent.type(screen.getByLabelText('Targets'), 'example.com, api.example.com')
    expect(start).toBeDisabled() // no scanner yet: nothing is hardcoded
    await userEvent.click(screen.getByLabelText('Scanner'))
    await userEvent.click(await screen.findByRole('option', { name: 'Nuclei' }))
    await userEvent.click(start)

    expect(quickScan).toHaveBeenCalledWith({
      targets: ['example.com', 'api.example.com'],
      scanner_name: 'nuclei',
    })
    expect(await screen.findByText('Scan started on 2 target(s)')).toBeInTheDocument()
    expect(saveQuickScan).not.toHaveBeenCalled()
  })

  it('a start the scope gate refuses lists each target with its reason, not a toast', async () => {
    quickScan.mockRejectedValue(
      Object.assign(new Error('You may not scan these targets: promo.net (...)'), {
        code: 'TARGET_OUT_OF_SCOPE',
        statusCode: 400,
        details: {
          refused: [
            { target: 'promo.net', code: 'no_entry', message: 'm', fixes: [] },
            { target: 'old.example.com', code: 'rejected', message: 'm', fixes: [] },
          ],
        },
      })
    )
    render(<QuickScanDialog open onOpenChange={vi.fn()} />)
    await userEvent.type(screen.getByLabelText('Targets'), 'promo.net, old.example.com')
    await userEvent.click(screen.getByLabelText('Scanner'))
    await userEvent.click(await screen.findByRole('option', { name: 'Nuclei' }))
    await userEvent.click(screen.getByRole('button', { name: /Start Scan/ }))

    expect(await screen.findByText('2 targets may not be scanned')).toBeInTheDocument()
    expect(screen.getByText('Not in scope')).toBeInTheDocument()
    expect(screen.getByText('Marked not ours')).toBeInTheDocument()
  })

  it('"Save as scan" saves the started scan under the chosen name', async () => {
    quickScan.mockResolvedValue({
      scan_run_id: 'r1',
      scan_id: 's1',
      status: 'pending',
      target_count: 1,
    })
    saveQuickScan.mockResolvedValue({ id: 's1', name: 'Nightly' })
    render(<QuickScanDialog open onOpenChange={vi.fn()} />)
    await userEvent.type(screen.getByLabelText('Targets'), 'example.com')
    await userEvent.click(screen.getByLabelText('Scanner'))
    await userEvent.click(await screen.findByRole('option', { name: 'Nuclei' }))
    await userEvent.click(screen.getByRole('button', { name: /Start Scan/ }))

    const name = await screen.findByLabelText('Save as scan')
    expect(name).toHaveValue('nuclei — example.com')
    await userEvent.clear(name)
    await userEvent.type(name, 'Nightly')
    await userEvent.click(screen.getByRole('button', { name: /Save/ }))

    expect(saveHookIds.at(-1)).toBe('s1')
    expect(saveQuickScan).toHaveBeenCalledWith({ name: 'Nightly' })
    expect(await screen.findByRole('link', { name: 'Nightly' })).toHaveAttribute(
      'href',
      '/scans/s1'
    )
  })
})

describe('defaultSaveName', () => {
  it('names the scanner and the first target', () => {
    expect(defaultSaveName('nuclei', ['a.com'])).toBe('nuclei — a.com')
    expect(defaultSaveName('nuclei', ['a.com', 'b.com', 'c.com'])).toBe('nuclei — a.com +2')
  })
})
