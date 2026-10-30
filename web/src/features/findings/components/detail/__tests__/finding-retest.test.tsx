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
let mockExtra: Record<string, unknown> = {}

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
      return {
        data: id ? { data: mockRetests, can_retest: mockCanRetest, ...mockExtra } : undefined,
      }
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
    mockExtra = {}
  })

  it('says a version-based finding is re-checked by reading the version again', async () => {
    mockExtra = {
      strategy: {
        kind: 'version_recheck',
        rule: 'CVE-2023-44487',
        tool: 'httpx',
        product: 'nginx',
        version: '1.25.2',
      },
    }
    render(
      <FindingRetestSection
        finding={{ id: 'f-9', toolName: 'version-match', ruleId: 'CVE-2023-44487', status: 'new' }}
      />
    )
    const button = screen.getByRole('button', { name: /Re-check version/i })
    expect(button).toHaveAttribute('title', expect.stringMatching(/^Re-check the detected version/))
    expect(button.getAttribute('title')).toContain('nginx')
    expect(
      screen.getByText(/runs httpx on the asset again to read the nginx version/)
    ).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /Active check/i })).not.toBeInTheDocument()
    await userEvent.click(button)
    await userEvent.click(
      within(await screen.findByRole('alertdialog')).getByRole('button', { name: 'Send retest' })
    )
    expect(mockTrigger).toHaveBeenCalledWith(undefined)
  })

  it('names the template a template retest runs', () => {
    mockExtra = { strategy: { kind: 'template', rule: 'exposed-admin-panel', tool: 'nuclei' } }
    render(<FindingRetestSection finding={nucleiFinding} />)
    expect(screen.getByRole('button', { name: /Retest now/i })).toHaveAttribute(
      'title',
      'Run the check exposed-admin-panel against the target'
    )
  })

  it('disables Retest with the reason for a finding a person reported', () => {
    mockCanRetest = false
    mockExtra = { strategy: { kind: 'none' }, reason: 'no_automatic_retest' }
    render(
      <FindingRetestSection
        finding={{ id: 'f-5', toolName: 'manual', status: 'new', source: 'manual' }}
      />
    )
    const button = screen.getByRole('button', { name: /Retest now/i })
    expect(button).toBeDisabled()
    expect(screen.getByText(/A person reported this finding/)).toBeInTheDocument()
    expect(mockTrigger).not.toHaveBeenCalled()
  })

  it('says why when no sensor has the template release, instead of offering a failing retest', () => {
    mockCanRetest = false
    mockExtra = {
      strategy: { kind: 'template', rule: 'exposed-admin-panel' },
      reason: 'no_template_sensor',
    }
    render(<FindingRetestSection finding={nucleiFinding} />)
    expect(screen.getByRole('button', { name: /Retest now/i })).toBeDisabled()
    expect(screen.getByText(/Update the sensor's templates/)).toBeInTheDocument()
  })

  it('shows no reason for a closed finding', () => {
    mockCanRetest = false
    mockExtra = { strategy: { kind: 'template' }, reason: 'status_not_eligible' }
    const { container } = render(
      <FindingRetestSection finding={{ ...nucleiFinding, status: 'false_positive' }} />
    )
    expect(container).toBeEmptyDOMElement()
  })

  it('offers the optional active check when an installed template is known', async () => {
    mockExtra = {
      strategy: {
        kind: 'version_recheck',
        rule: 'CVE-2021-41773',
        tool: 'httpx',
        product: 'Apache httpd',
      },
      active_check: { template: 'CVE-2021-41773', available: true },
    }
    render(
      <FindingRetestSection
        finding={{ id: 'f-9', toolName: 'version-match', ruleId: 'CVE-2021-41773', status: 'new' }}
      />
    )
    const active = screen.getByRole('button', { name: /Active check/i })
    expect(active).toHaveAttribute('title', expect.stringContaining('CVE-2021-41773'))
    await userEvent.click(active)
    const dialog = await screen.findByRole('alertdialog')
    expect(dialog).toHaveTextContent(/active check/i)
    await userEvent.click(within(dialog).getByRole('button', { name: 'Send retest' }))
    expect(mockTrigger).toHaveBeenCalledWith('active_check')
    expect(document.body.textContent).not.toMatch(/ \u00b7 |\u2014/)
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
    // The API decides (can_retest false); the console no longer guesses from the tool.
    mockCanRetest = false
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
  beforeEach(() => {
    mockExtra = {}
  })

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
    mockCanRetest = false
    mockExtra = { strategy: { kind: 'none' }, reason: 'no_automatic_retest' }
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
