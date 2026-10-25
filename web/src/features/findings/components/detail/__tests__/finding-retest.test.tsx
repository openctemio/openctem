/**
 * Retest section (RFC-039)
 * - "Retest now" needs findings:verify and a retestable (nuclei) finding
 * - pressing it requests a retest
 * - the latest retest reads fixed / still present / regression / unknown / running
 * - nothing renders for a finding that can never be retested and has no history
 */

import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { FindingRetestSection, retestMeta } from '../finding-retest'
import type { FindingRetest } from '../../../api/use-finding-retests'

const mockTrigger = vi.fn()
let mockRetests: FindingRetest[] = []
let mockCanRetest = true
let mockHasPermission = (_: string) => true
let mockRetestsFor: string | null = null
let mockCheck: { id: string; template_name: string } | null = null

vi.mock('../../../api/use-finding-retest-check', async (importOriginal) => {
  const real = await importOriginal<typeof import('../../../api/use-finding-retest-check')>()
  return { ...real, useFindingRetestCheck: () => ({ data: { check: mockCheck } }) }
})

vi.mock('../../../api/use-finding-retests', async (importOriginal) => {
  const real = await importOriginal<typeof import('../../../api/use-finding-retests')>()
  return {
    ...real,
    useFindingRetests: (id: string | null) => {
      mockRetestsFor = id
      return { data: id ? { data: mockRetests, can_retest: mockCanRetest } : undefined }
    },
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
    mockCanRetest = true
    mockHasPermission = () => true
    mockCheck = null
    mockRetestsFor = null
  })

  it('offers Retest now on a nuclei finding to a user with findings:verify', async () => {
    render(<FindingRetestSection finding={nucleiFinding} />)
    expect(screen.getByText(/Not retested yet/i)).toBeInTheDocument()
    await userEvent.click(screen.getByRole('button', { name: /Retest now/i }))
    // Traffic is sent only after the confirmation.
    expect(mockTrigger).not.toHaveBeenCalled()
    const dialog = await screen.findByRole('alertdialog')
    expect(dialog).toHaveTextContent(/sends scan traffic/i)
    await userEvent.click(within(dialog).getByRole('button', { name: 'Send retest' }))
    expect(mockTrigger).toHaveBeenCalledTimes(1)
  })

  it('offers Retest now on any tool the API says can be re-checked', async () => {
    render(
      <FindingRetestSection
        finding={{ id: 'f-3', toolName: 'trivy', ruleId: 'CVE-2026-0001', status: 'confirmed' }}
      />
    )
    await userEvent.click(screen.getByRole('button', { name: /Retest now/i }))
    await userEvent.click(
      within(await screen.findByRole('alertdialog')).getByRole('button', { name: 'Send retest' })
    )
    expect(mockTrigger).toHaveBeenCalledTimes(1)
  })

  it('hides Retest now when no sensor of the organization can re-check the finding', () => {
    mockCanRetest = false
    render(<FindingRetestSection finding={nucleiFinding} />)
    expect(screen.queryByRole('button', { name: /Retest now/i })).not.toBeInTheDocument()
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

  it('offers Retest now on a finding without a tool rule once a retest check is attached', async () => {
    mockCheck = { id: 'c-1', template_name: 'Reflected XSS on /search' }
    render(<FindingRetestSection finding={{ id: 'f-3', status: 'confirmed', source: 'manual' }} />)
    expect(mockRetestsFor).toBe('f-3')
    expect(screen.getByText(/runs the custom check Reflected XSS on \/search/)).toBeInTheDocument()
    await userEvent.click(screen.getByRole('button', { name: /Retest now/i }))
    await userEvent.click(
      within(await screen.findByRole('alertdialog')).getByRole('button', { name: 'Send retest' })
    )
    expect(mockTrigger).toHaveBeenCalledTimes(1)
  })

  it('names the custom check on a retest that ran it', () => {
    mockCheck = { id: 'c-1', template_name: 'Reflected XSS on /search' }
    mockRetests = [
      retest({
        outcome: 'still_vulnerable',
        retest_check_id: 'c-1',
        check_digest: 'sha256:abcdef1234567890',
      } as Partial<FindingRetest>),
    ]
    render(<FindingRetestSection finding={nucleiFinding} />)
    expect(
      screen.getByText(/Checked with custom check Reflected XSS on \/search/)
    ).toBeInTheDocument()
    expect(screen.getByText('(sha256:abcdef123456)')).toBeInTheDocument()
  })

  it('shows still exposed at another path as its own amber outcome with its help', () => {
    mockRetests = [
      retest({
        outcome: 'still_exposed_elsewhere',
        reason_code: 'matched_elsewhere',
        reason: 'matched at /a and /b',
        result_status: 'confirmed',
      }),
    ]
    render(<FindingRetestSection finding={nucleiFinding} />)
    const chip = screen.getByText('Still exposed at another path')
    expect(chip.className).toMatch(/sev-medium/)
    expect(screen.getByText(/matched at \/a and \/b/)).toBeInTheDocument()
    expect(screen.getByText(/matched at another path of the same target/)).toBeInTheDocument()
    expect(screen.queryByText(/Inconclusive/)).toBeNull()
  })

  it('words an endpoint mismatch in plain language', () => {
    mockRetests = [
      retest({
        outcome: 'inconclusive',
        reason_code: 'endpoint_mismatch',
        result_status: 'confirmed',
      }),
    ]
    render(<FindingRetestSection finding={nucleiFinding} />)
    expect(
      screen.getByText("Inconclusive: the check did not request this finding's endpoint")
    ).toBeInTheDocument()
    expect(screen.getByText(/pinned to the exact URL of the finding/)).toBeInTheDocument()
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

  it('says what an inconclusive retest means and what to do, for each reason the tool gives', () => {
    for (const [code, label, help] of [
      [
        'template_not_found',
        'Inconclusive: check not installed on the sensor',
        /template set does not include this check.*Update the sensor's templates/,
      ],
      [
        'excluded_by_policy',
        'Inconclusive: check not allowed by the sensor policy',
        /safety policy never runs checks of its class.*Verify it by hand/,
      ],
      [
        'no_verdict',
        'Inconclusive: the tool gave no verdict',
        /ended without a verdict.*Retest again/,
      ],
    ] as const) {
      mockRetests = [
        retest({
          outcome: 'inconclusive',
          reason_code: code,
          reason: 'sensor detail',
          result_status: 'confirmed',
        }),
      ]
      const { unmount } = render(<FindingRetestSection finding={nucleiFinding} />)
      expect(screen.getByText(label)).toBeInTheDocument()
      expect(screen.getByText(help)).toBeInTheDocument()
      unmount()
    }
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
      retestMeta(retest({ outcome: 'confirmed_fixed', result_status: 'confirmed' })).label
    ).toBe('Verified fixed, awaiting confirmation')
    expect(
      retestMeta(retest({ outcome: 'confirmed_fixed', result_status: 'resolved' })).label
    ).toBe('Fixed: verified and resolved')
    expect(retestMeta(retest({ outcome: 'not_reproduced' })).label).toBe(
      'Not reproduced, not confirmed'
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
    ).toBe("Inconclusive: the check did not request this finding's endpoint")
    expect(retestMeta(retest({ outcome: 'inconclusive', reason_code: 'blocked' })).label).toBe(
      'Inconclusive: blocked'
    )
    expect(retestMeta(retest({ outcome: 'inconclusive' })).label).toBe('Inconclusive')
    expect(retestMeta(retest({ status: 'pending' })).label).toBe('Retest running')
  })

  it('lists earlier attempts one line each, with chip, reason and no separators', () => {
    mockRetests = [
      retest({
        id: 'r-3',
        outcome: 'inconclusive',
        reason_code: 'access_denied',
        reason: 'answered 403: access denied by the server',
      }),
      retest({
        id: 'r-2',
        outcome: 'inconclusive',
        reason_code: 'edge_blocked',
        reason: 'answered 403: the cloudflare edge protection stopped the request',
      }),
      retest({ id: 'r-1', outcome: 'still_vulnerable', reason: 'matched again' }),
    ]
    render(<FindingRetestSection finding={nucleiFinding} />)
    const history = document.querySelector('[data-slot="retest-history"]') as HTMLElement
    const rows = within(history).getAllByRole('listitem')
    expect(rows).toHaveLength(2)
    expect(within(rows[0]).getByText('Inconclusive: blocked by edge protection')).toBeTruthy()
    expect(within(rows[0]).getByText(/cloudflare edge protection/)).toBeTruthy()
    expect(within(rows[1]).getByText('Still vulnerable')).toBeTruthy()
    expect(history.textContent).not.toContain('·')
  })

  it('explains an origin access refusal on the latest retest', () => {
    mockRetests = [
      retest({
        id: 'r-9',
        outcome: 'inconclusive',
        reason_code: 'access_denied',
        reason: 'answered 403: access denied by the server',
      }),
    ]
    render(<FindingRetestSection finding={nucleiFinding} />)
    const help = document.querySelector('[data-slot="retest-inconclusive-help"]') as HTMLElement
    expect(help.textContent).toMatch(/One refusal is not proof of a fix/)
    expect(help.textContent).toMatch(/at least an hour later/)
  })

  it("shows a pentest finding's manual retests with the tester's notes", () => {
    mockRetests = [
      retest({
        id: 'm-1',
        kind: 'manual',
        manual_result: 'partial',
        notes: 'login fixed, API not',
      }),
    ]
    render(
      <FindingRetestSection finding={{ id: 'f-2', source: 'pentest', status: 'fix_applied' }} />
    )
    expect(screen.getByText('Tester retest: partially fixed')).toBeTruthy()
    expect(screen.getByText('login fixed, API not')).toBeTruthy()
    expect(screen.queryByText('View evidence')).toBeNull()
    expect(screen.queryByText('Retest now')).toBeNull()
  })
})
