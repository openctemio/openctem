/**
 * The finding page's main action follows the finding's state, and each one
 * keeps the gate it has elsewhere on the page (finding-main-action.tsx).
 */
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import type { FindingDetail } from '../../../types'

let canMutate = true
let moduleOn = true
let mayVerify = true
let retests: { can_retest?: boolean; data?: { status: string }[] } | undefined
const requestRetest = vi.fn()
const fetchTransitions = vi.fn()
const toastError = vi.fn()

vi.mock('next/navigation', () => ({
  useRouter: () => ({ push: vi.fn() }),
  usePathname: () => '/',
  useSearchParams: () => new URLSearchParams(),
}))
vi.mock('sonner', () => ({ toast: { success: vi.fn(), error: (m: string) => toastError(m) } }))
vi.mock('@/lib/permissions', async (orig) => ({
  ...(await orig<typeof import('@/lib/permissions')>()),
  useCanMutate: () => canMutate,
}))
vi.mock('@/features/integrations/api/use-tenant-modules', () => ({
  useModuleEnabled: () => moduleOn,
}))
vi.mock('@/context/permission-provider', () => ({
  usePermissions: () => ({ hasPermission: (p: string) => p === 'findings:verify' && mayVerify }),
}))
vi.mock('../../../api/use-finding-retests', () => ({
  useFindingRetests: (id: string | null) => ({ data: id ? retests : undefined }),
  useRequestRetest: () => ({ trigger: requestRetest, isMutating: false }),
}))
vi.mock('../../../api/use-finding-retest-check', () => ({
  useFindingRetestCheck: () => ({ data: undefined }),
}))
vi.mock('../../../api/triage-api', () => ({
  fetchTransitions: (id: string) => fetchTransitions(id),
}))
vi.mock('@/features/remediation-hub/components/add-findings-to-task-dialog', () => ({
  AddFindingsToTaskDialog: ({ findings }: { findings: { id: string }[] }) => (
    <div role="dialog">{findings.map((f) => f.id).join(',')}</div>
  ),
}))

const { FindingMainAction } = await import('../finding-main-action')

const base = { id: 'f1', title: 'Heartbleed', source: 'va', assets: [] }
const finding = (extra: Partial<FindingDetail> = {}) =>
  ({ ...base, ...extra }) as unknown as FindingDetail

beforeEach(() => {
  canMutate = true
  moduleOn = true
  mayVerify = true
  retests = { can_retest: true, data: [] }
  requestRetest.mockReset().mockResolvedValue({})
  fetchTransitions.mockReset()
  toastError.mockReset()
})

describe('FindingMainAction', () => {
  it('opens the original of a duplicate', () => {
    render(<FindingMainAction finding={finding({ duplicateOf: 'f0' })} status="duplicate" />)
    expect(screen.getByRole('link', { name: 'Open the original' })).toHaveAttribute(
      'href',
      '/findings/f0'
    )
    expect(screen.queryByRole('button', { name: 'Add to task' })).toBeNull()
  })

  it('offers Retest now for an applied fix and sends the retest after the confirm', async () => {
    render(<FindingMainAction finding={finding()} status="fix_applied" />)
    await userEvent.click(screen.getByRole('button', { name: 'Retest now' }))
    await userEvent.click(screen.getByRole('button', { name: 'Send retest' }))
    expect(requestRetest).toHaveBeenCalledWith(undefined)
  })

  it('falls back to Add to task when the retest cannot run or the viewer may not verify', () => {
    retests = { can_retest: false, data: [] }
    const { unmount } = render(<FindingMainAction finding={finding()} status="fix_applied" />)
    expect(screen.queryByRole('button', { name: 'Retest now' })).toBeNull()
    expect(screen.getByRole('button', { name: 'Add to task' })).toBeInTheDocument()
    unmount()
    retests = { can_retest: true, data: [] }
    mayVerify = false
    render(<FindingMainAction finding={finding()} status="fix_applied" />)
    expect(screen.queryByRole('button', { name: 'Retest now' })).toBeNull()
  })

  it('marks the fix applied through the lifecycle move the server allows', async () => {
    const move = { to: 'fix_applied', allowed: true, mode: 'direct' }
    fetchTransitions.mockResolvedValue({ status: 'in_progress', transitions: [move] })
    const onStatusMove = vi.fn()
    render(
      <FindingMainAction finding={finding()} status="in_progress" onStatusMove={onStatusMove} />
    )
    await userEvent.click(screen.getByRole('button', { name: 'Mark fix applied' }))
    expect(fetchTransitions).toHaveBeenCalledWith('f1')
    expect(onStatusMove).toHaveBeenCalledWith('fix_applied', move)
  })

  it('says why when the lifecycle blocks the move, and writes nothing', async () => {
    fetchTransitions.mockResolvedValue({
      status: 'in_progress',
      transitions: [{ to: 'fix_applied', allowed: false, blocked: [{ code: 'x' }] }],
    })
    const onStatusMove = vi.fn()
    render(
      <FindingMainAction finding={finding()} status="in_progress" onStatusMove={onStatusMove} />
    )
    await userEvent.click(screen.getByRole('button', { name: 'Mark fix applied' }))
    expect(onStatusMove).not.toHaveBeenCalled()
    expect(toastError).toHaveBeenCalled()
  })

  it('never offers Mark fix applied without the status permission or on a people-written finding', () => {
    const onStatusMove = vi.fn()
    const { unmount } = render(
      <FindingMainAction
        finding={finding({ source: 'pentest' })}
        status="in_progress"
        onStatusMove={onStatusMove}
      />
    )
    expect(screen.queryByRole('button', { name: 'Mark fix applied' })).toBeNull()
    unmount()
    canMutate = false
    render(
      <FindingMainAction finding={finding()} status="in_progress" onStatusMove={onStatusMove} />
    )
    expect(screen.queryByRole('button', { name: 'Mark fix applied' })).toBeNull()
    // Without the task permission there is no main action at all.
    expect(screen.queryByRole('button', { name: 'Add to task' })).toBeNull()
  })

  it('shows Add to task otherwise, only with the remediation module', async () => {
    const { unmount } = render(<FindingMainAction finding={finding()} status="new" />)
    await userEvent.click(screen.getByRole('button', { name: 'Add to task' }))
    expect(screen.getByRole('dialog')).toHaveTextContent('f1')
    unmount()
    moduleOn = false
    render(<FindingMainAction finding={finding()} status="new" />)
    expect(screen.queryByRole('button', { name: 'Add to task' })).toBeNull()
  })
})
