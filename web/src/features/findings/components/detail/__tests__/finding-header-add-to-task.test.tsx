/**
 * The finding page offers "Add to task" (it was only on the list and in
 * triage): shown only with the task write permission and the remediation
 * module, and it opens the shared dialog for this one finding.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import type { FindingDetail } from '../../../types'

let canMutate = true
let moduleOn = true
vi.mock('next/navigation', () => ({
  useRouter: () => ({ push: vi.fn() }),
  usePathname: () => '/',
  useSearchParams: () => new URLSearchParams(),
}))
vi.mock('@/lib/permissions', async (orig) => ({
  ...(await orig<typeof import('@/lib/permissions')>()),
  useCanMutate: () => canMutate,
}))
vi.mock('@/features/integrations/api/use-tenant-modules', () => ({
  useModuleEnabled: () => moduleOn,
}))
vi.mock('@/context/permission-provider', () => ({
  usePermissions: () => ({ hasPermission: () => false }),
}))
vi.mock('@/context/tenant-provider', () => ({
  useTenant: () => ({ currentTenant: { id: 't' } }),
  useCurrentTenantId: () => 't',
}))
vi.mock('@/features/ai-triage/components', () => ({ AITriageButton: () => null }))
vi.mock('../../create-ticket-dialog', () => ({ CreateTicketDialog: () => null }))
vi.mock('../../mark-duplicate-dialog', () => ({ MarkDuplicateDialog: () => null }))
vi.mock('../../../hooks/use-can-create-ticket', () => ({ useCanCreateTicket: () => false }))
vi.mock('@/features/remediation-hub/components/add-findings-to-task-dialog', () => ({
  AddFindingsToTaskDialog: ({ findings }: { findings: { id: string; title: string }[] }) => (
    <div role="dialog">{findings.map((f) => `${f.id}:${f.title}`).join(',')}</div>
  ),
}))

const { FindingHeader } = await import('../finding-header')

const finding = {
  id: 'f1',
  title: 'Heartbleed',
  source: 'va',
  assets: [],
} as unknown as FindingDetail

beforeEach(() => {
  canMutate = true
  moduleOn = true
})

describe('Add to task on the finding page', () => {
  it('opens the shared dialog for this finding', async () => {
    render(<FindingHeader finding={finding} status="new" />)
    await userEvent.click(screen.getByRole('button', { name: 'Add to task' }))
    expect(screen.getByRole('dialog')).toHaveTextContent('f1:Heartbleed')
  })

  it('is hidden without the task permission', () => {
    canMutate = false
    render(<FindingHeader finding={finding} status="new" />)
    expect(screen.queryByRole('button', { name: 'Add to task' })).toBeNull()
  })

  it('is hidden when the remediation module is off', () => {
    moduleOn = false
    render(<FindingHeader finding={finding} status="new" />)
    expect(screen.queryByRole('button', { name: 'Add to task' })).toBeNull()
  })
})
