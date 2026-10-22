/**
 * A section whose read failed shows an error row with Retry instead of an
 * empty state; a 403/404 refusal stays hidden (no oracle).
 */
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { ApiClientError } from '@/lib/api/error-handler'
import { FindingRetestCheckSection } from '../finding-retest-check'
import { FindingTicketLinks } from '../finding-ticket-links'
import { FindingTaskBand } from '@/features/remediation-hub/components/finding-task-band'

let mockError: unknown
const retry = vi.fn()

vi.mock('../../../api/use-finding-retest-check', async (orig) => ({
  ...(await orig<typeof import('../../../api/use-finding-retest-check')>()),
  useFindingRetestCheck: () => ({
    data: undefined,
    error: mockError,
    isLoading: false,
    mutate: retry,
  }),
  useRemoveRetestCheck: () => ({ trigger: vi.fn(), isMutating: false }),
}))
vi.mock('../../../api/use-finding-retests', () => ({ useFindingRetests: () => ({ data: null }) }))
vi.mock('swr', async (orig) => ({
  ...(await orig<typeof import('swr')>()),
  default: () => ({ data: undefined, error: mockError, mutate: retry }),
}))
vi.mock('@/features/remediation-hub/api/use-remediation-hub', () => ({
  useTasks: () => ({ data: undefined, error: mockError, mutate: retry }),
}))
vi.mock('@/lib/permissions', () => ({ Permission: { RemediationRead: 'remediation:read' } }))
vi.mock('@/context/permission-provider', () => ({
  usePermissions: () => ({ hasPermission: () => true }),
}))
vi.mock('@/context/tenant-provider', () => ({ useTenant: () => ({ currentTenant: { id: 't' } }) }))
vi.mock('../../create-ticket-dialog', () => ({ CreateTicketDialog: () => null }))
vi.mock('../../../hooks/use-can-create-ticket', () => ({ useCanCreateTicket: () => false }))
vi.mock('@/features/integrations/api/use-ticket-create-policy', () => ({
  useFindingTicketHolds: () => ({ data: undefined }),
}))

const cases: Array<[string, () => React.ReactElement]> = [
  ['retest check', () => <FindingRetestCheckSection finding={{ id: 'f-1' }} />],
  ['ticket links', () => <FindingTicketLinks findingId="f-1" />],
  ['task band', () => <FindingTaskBand findingId="f-1" />],
]

describe.each(cases)('%s load error', (_name, make) => {
  beforeEach(() => retry.mockReset())

  it('500 shows an error row and Retry refetches', async () => {
    mockError = new ApiClientError('boom', 'INTERNAL', 500)
    render(make())
    expect(screen.getByTestId('section-load-error')).toBeInTheDocument()
    await userEvent.click(screen.getByRole('button', { name: 'Retry' }))
    expect(retry).toHaveBeenCalledTimes(1)
  })

  it('network failure (no status) shows the row too', () => {
    mockError = new Error('network')
    render(make())
    expect(screen.getByTestId('section-load-error')).toBeInTheDocument()
  })

  it('404 / 403 show no error row', () => {
    for (const status of [403, 404]) {
      mockError = new ApiClientError('x', 'X', status)
      const { unmount } = render(make())
      expect(screen.queryByTestId('section-load-error')).not.toBeInTheDocument()
      unmount()
    }
  })
})
