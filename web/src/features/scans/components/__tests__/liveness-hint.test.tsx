/**
 * The scan detail page suggests live hosts first for a saved scan that
 * sweeps its ranges while it could find the live hosts first; it never
 * switches the scan on its own.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import { LivenessHint } from '../liveness-hint'
import { Permission } from '@/lib/permissions'
import type { ScanConfig } from '@/lib/api/scan-types'

let perms: string[] = []
vi.mock('@/lib/permissions/hooks', () => ({
  usePermissions: () => ({
    permissions: perms,
    can: (p: string) => perms.includes(p),
    canAny: (...p: string[]) => p.some((x) => perms.includes(x)),
    canAll: (...p: string[]) => p.every((x) => perms.includes(x)),
    isAtLeast: () => false,
    isLoading: false,
    tenantRole: 'member',
  }),
}))
vi.mock('sonner', () => ({ toast: { success: vi.fn(), error: vi.fn() } }))

let workflow: unknown = undefined
vi.mock('@/lib/api/scan-workflow-hooks', () => ({
  useScanWorkflow: (id: string | null) => ({ data: id ? workflow : undefined }),
}))
const put = vi.fn()
vi.mock('@/lib/api/client', () => ({ put: (...a: unknown[]) => put(...a) }))

const base = {
  id: 's1',
  scan_type: 'workflow',
  scan_workflow_id: 'wf1',
  targets: ['203.0.113.0/24'],
} as unknown as ScanConfig

describe('LivenessHint', () => {
  beforeEach(() => {
    perms = [Permission.ScansRead, Permission.ScansWrite]
    workflow = { steps: [{ capabilities: ['discover.hosts'] }, { capabilities: ['scan.ports'] }] }
    put.mockReset()
  })

  it('suggests live hosts first and switches with one click', async () => {
    put.mockResolvedValue({})
    const onChanged = vi.fn()
    render(<LivenessHint config={base} onChanged={onChanged} />)
    expect(screen.getByTestId('liveness-hint')).toHaveTextContent('Live hosts first (recommended)')
    expect(put).not.toHaveBeenCalled()
    await userEvent.click(screen.getByRole('button', { name: 'Use live hosts first' }))
    expect(put).toHaveBeenCalledWith('/api/v1/scans/s1', {
      target_options: { cidr_mode: 'liveness' },
    })
    await waitFor(() => expect(onChanged).toHaveBeenCalled())
  })

  it('keeps the other target options when it switches', async () => {
    put.mockResolvedValue({})
    render(
      <LivenessHint
        config={{ ...base, target_options: { cidr_mode: 'sweep', include_stale: true } }}
        onChanged={vi.fn()}
      />
    )
    await userEvent.click(screen.getByRole('button', { name: 'Use live hosts first' }))
    expect(put).toHaveBeenCalledWith('/api/v1/scans/s1', {
      target_options: { cidr_mode: 'liveness', include_stale: true },
    })
  })

  it.each([
    [
      'a scan that already finds live hosts first',
      { ...base, target_options: { cidr_mode: 'liveness' } },
    ],
    ['a scan without ranges', { ...base, targets: ['example.com'] }],
    ['known hosts only', { ...base, target_options: { cidr_mode: 'inventory' } }],
  ])('shows nothing for %s', (_name, config) => {
    const { container } = render(<LivenessHint config={config as ScanConfig} onChanged={vi.fn()} />)
    expect(container).toBeEmptyDOMElement()
  })

  it('shows nothing when the workflow has no Host discovery step', () => {
    workflow = { steps: [{ capabilities: ['scan.ports'] }] }
    const { container } = render(<LivenessHint config={base} onChanged={vi.fn()} />)
    expect(container).toBeEmptyDOMElement()
  })

  it('a reader sees the hint but cannot switch', () => {
    perms = [Permission.ScansRead]
    render(<LivenessHint config={base} onChanged={vi.fn()} />)
    expect(screen.getByText('Use live hosts first').closest('button')).toBeDisabled()
  })
})
