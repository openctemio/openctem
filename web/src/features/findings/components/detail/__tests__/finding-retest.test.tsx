/**
 * Retest section (RFC-039)
 * - "Retest now" needs findings:verify and a retestable (nuclei) finding
 * - pressing it requests a retest
 * - the latest retest reads fixed / still present / regression / unknown / running
 * - nothing renders for a finding that can never be retested and has no history
 */

import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { FindingRetestSection, retestMeta } from '../finding-retest'
import type { FindingRetest } from '../../../api/use-finding-retests'

const mockTrigger = vi.fn()
let mockRetests: FindingRetest[] = []
let mockHasPermission = (_: string) => true

vi.mock('../../../api/use-finding-retests', async (importOriginal) => {
  const real = await importOriginal<typeof import('../../../api/use-finding-retests')>()
  return {
    ...real,
    useFindingRetests: () => ({ data: { data: mockRetests } }),
    useRequestRetest: () => ({ trigger: mockTrigger, isMutating: false }),
  }
})

vi.mock('swr', () => ({ useSWRConfig: () => ({ mutate: vi.fn() }) }))

vi.mock('@/context/permission-provider', () => ({
  usePermissions: () => ({ hasPermission: (p: string) => mockHasPermission(p) }),
}))

vi.mock('sonner', () => ({ toast: { success: vi.fn(), error: vi.fn() } }))

vi.mock('../../../api/use-finding-evidence-items', () => ({
  useFindingEvidenceItems: () => ({ data: { data: [] }, isLoading: false }),
  revealEvidence: vi.fn(),
}))

const nucleiFinding = {
  id: 'f-1',
  toolName: 'nuclei',
  ruleId: 'exposed-admin-panel',
  status: 'confirmed',
}

function retest(over: Partial<FindingRetest>): FindingRetest {
  return {
    id: 'r-1',
    finding_id: 'f-1',
    trigger: 'manual',
    status: 'completed',
    prior_status: 'confirmed',
    template_id: 'exposed-admin-panel',
    target: 'https://shop.example.com/admin',
    created_at: '2026-10-03T00:00:00Z',
    ...over,
  }
}

describe('FindingRetestSection', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockTrigger.mockResolvedValue(retest({ status: 'pending' }))
    mockRetests = []
    mockHasPermission = () => true
  })

  it('offers Retest now on a nuclei finding to a user with findings:verify', async () => {
    render(<FindingRetestSection finding={nucleiFinding} />)
    expect(screen.getByText(/Not retested yet/i)).toBeInTheDocument()
    await userEvent.click(screen.getByRole('button', { name: /Retest now/i }))
    expect(mockTrigger).toHaveBeenCalledTimes(1)
  })

  it('hides Retest now without findings:verify', () => {
    mockHasPermission = (p) => p !== 'findings:verify'
    render(<FindingRetestSection finding={nucleiFinding} />)
    expect(screen.queryByRole('button', { name: /Retest now/i })).not.toBeInTheDocument()
  })

  it('renders nothing for a finding with no deterministic re-check and no history', () => {
    const { container } = render(
      <FindingRetestSection finding={{ id: 'f-2', toolName: 'trivy', status: 'confirmed' }} />
    )
    expect(container).toBeEmptyDOMElement()
  })

  it('shows an unreachable target as inconclusive, with the reason', () => {
    mockRetests = [
      retest({
        outcome: 'inconclusive',
        reason_code: 'unreachable',
        reason: 'target unreachable: connection refused',
        result_status: 'confirmed',
      }),
    ]
    render(<FindingRetestSection finding={nucleiFinding} />)
    expect(screen.getByText('Inconclusive: target unreachable')).toBeInTheDocument()
    expect(screen.getByText(/connection refused/i)).toBeInTheDocument()
  })

  it('disables Retest now while a retest is running', () => {
    mockRetests = [retest({ status: 'pending' })]
    render(<FindingRetestSection finding={nucleiFinding} />)
    expect(screen.getByText('Retest running')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /Retest now/i })).toBeDisabled()
  })
})

describe('retestMeta', () => {
  it('links the retest run to a user who can read scans', () => {
    mockRetests = [retest({ outcome: 'still_vulnerable', run_id: 'run-1' })]
    render(<FindingRetestSection finding={nucleiFinding} />)
    expect(screen.getByRole('link', { name: 'View run' })).toHaveAttribute(
      'href',
      '/scans/runs?run=run-1'
    )
  })

  it('shows no run link without scans:read or without a run', () => {
    mockRetests = [retest({ outcome: 'still_vulnerable', run_id: 'run-1' })]
    mockHasPermission = (p) => p !== 'scans:read'
    const { unmount } = render(<FindingRetestSection finding={nucleiFinding} />)
    expect(screen.queryByRole('link', { name: 'View run' })).not.toBeInTheDocument()
    unmount()
    mockHasPermission = () => true
    mockRetests = [retest({ outcome: 'still_vulnerable' })]
    render(<FindingRetestSection finding={nucleiFinding} />)
    expect(screen.queryByRole('link', { name: 'View run' })).not.toBeInTheDocument()
  })

  it('labels each outcome; only a confirmed fix reads as fixed', () => {
    expect(
      retestMeta(retest({ outcome: 'confirmed_fixed', result_status: 'validated_fixed' })).label
    ).toBe('Verified fixed — awaiting confirmation')
    expect(
      retestMeta(retest({ outcome: 'confirmed_fixed', result_status: 'resolved' })).label
    ).toBe('Fixed — verified and resolved')
    expect(retestMeta(retest({ outcome: 'not_reproduced' })).label).toBe(
      'Not reproduced — not confirmed'
    )
    expect(retestMeta(retest({ outcome: 'still_vulnerable' })).label).toBe('Still vulnerable')
    expect(
      retestMeta(
        retest({
          outcome: 'still_vulnerable',
          prior_status: 'resolved',
          result_status: 'confirmed',
        })
      ).label
    ).toMatch(/Regression/)
    expect(
      retestMeta(retest({ outcome: 'inconclusive', reason_code: 'endpoint_mismatch' })).label
    ).toBe('Inconclusive: another endpoint was checked')
    expect(retestMeta(retest({ outcome: 'inconclusive', reason_code: 'blocked' })).label).toBe(
      'Inconclusive: blocked'
    )
    expect(retestMeta(retest({ outcome: 'inconclusive' })).label).toBe('Inconclusive')
    expect(retestMeta(retest({ status: 'pending' })).label).toBe('Retest running')
  })
})
