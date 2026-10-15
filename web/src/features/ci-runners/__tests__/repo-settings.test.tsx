import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import { CIRepositorySettingsTab } from '../components/ci-repo-settings'
import { CIRunSheet } from '../components/ci-runs-view'
import { PolicyLocks } from '../components/ci-trust-settings'
import { pipelineTab } from '../components/ci-pipeline-sheet'
import {
  allowedCapabilityModes,
  allowedOptions,
  baselineCounts,
  baselineDueAt,
  fieldLoosens,
  missingCodeHost,
  needsReasonError,
  overrideWrite,
  resetWrite,
  runAttempts,
  validEndDate,
  validReason,
} from '../lib/gate-settings'
import { pipelinesURL } from '../lib/pipeline'
import type { CIGatePolicy } from '../types'

// ── mocks ──────────────────────────────────────────────────

let settings: unknown
let baseline: unknown = null
let runDetail: unknown
const mockSave = vi.fn()
const mockDelete = vi.fn()

vi.mock('../api/use-ci', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../api/use-ci')>()),
  useRepositoryGateSettings: () => ({ data: settings, isLoading: false, mutate: vi.fn() }),
  useGateBaseline: () => ({ data: baseline, isLoading: false, mutate: vi.fn() }),
  useRecordGateBaseline: () => ({ trigger: vi.fn(), isMutating: false }),
  useDeleteGateBaseline: () => ({ trigger: vi.fn(), isMutating: false }),
  useSaveGatePolicy: () => ({ trigger: mockSave, isMutating: false }),
  useDeleteGatePolicy: () => ({ trigger: mockDelete, isMutating: false }),
  useCIRun: (id: string | null) => ({ data: id ? runDetail : undefined }),
}))

let perms: string[] = []
vi.mock('@/lib/permissions', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@/lib/permissions')>()),
  usePermissions: () => ({ can: (p: string) => perms.includes(p), isLoading: false }),
}))

vi.mock('@/context/tenant-provider', () => ({
  useTenant: () => ({ currentTenant: { id: 't-123', slug: 'acme', role: 'owner' } }),
}))
vi.mock('sonner', () => ({ toast: { success: vi.fn(), error: vi.fn() } }))
vi.mock('next/link', () => ({
  default: ({ href, children, ...rest }: { href: string; children: React.ReactNode }) => (
    <a href={href} {...rest}>
      {children}
    </a>
  ),
}))

const REPO = '11111111-2222-3333-4444-555555555555'

const repoPolicy: CIGatePolicy = {
  id: 'pol-repo',
  scope_type: 'repository',
  scope_id: REPO,
  mode: 'enforce',
  fail_on_severity: 'critical',
  new_findings_only: true,
  fail_on_kev: true,
  epss_threshold: 0.4,
  fixable_only: false,
  allow_repo_policy: true,
  baseline_on_first_run: false,
  baseline_grace_days: 30,
  baseline_secrets_block: true,
  fields: ['fail_on_severity', 'new_findings_only'],
  reason: 'Legacy service, retiring in Q1',
  expires_at: '2027-01-31T23:59:59Z',
}

function fieldsFixture() {
  return [
    { field: 'mode', value: 'enforce', inherited: 'enforce', source: 'tenant' },
    {
      field: 'fail_on_severity',
      value: 'high',
      inherited: 'high',
      source: 'tenant',
      locked_by: 'tenant',
      ignored: true,
    },
    {
      field: 'new_findings_only',
      value: true,
      inherited: false,
      source: 'repository',
      policy_id: 'pol-repo',
    },
    { field: 'fail_on_kev', value: true, inherited: true, source: 'default' },
    { field: 'epss_threshold', value: null, inherited: null, source: 'default' },
  ]
}

beforeEach(() => {
  perms = ['scans:ci:read', 'scans:ci:policy']
  baseline = null
  mockSave.mockReset()
  mockDelete.mockReset()
  settings = {
    repository_asset_id: REPO,
    source: 'repository',
    fields: fieldsFixture(),
    repository: repoPolicy,
    checked_at: '2026-10-15T00:00:00Z',
  }
})

// ── lib ────────────────────────────────────────────────────

describe('gate settings rules', () => {
  it('mirrors the API on what loosens a field', () => {
    expect(fieldLoosens('fail_on_severity', 'high', 'critical')).toBe(true)
    expect(fieldLoosens('fail_on_severity', 'high', 'none')).toBe(true)
    expect(fieldLoosens('fail_on_severity', 'high', 'medium')).toBe(false)
    expect(fieldLoosens('mode', 'enforce', 'warn')).toBe(true)
    expect(fieldLoosens('mode', 'warn', 'enforce')).toBe(false)
    expect(fieldLoosens('new_findings_only', false, true)).toBe(true)
    expect(fieldLoosens('fail_on_kev', true, false)).toBe(true)
    expect(fieldLoosens('epss_threshold', 0.3, 0.5)).toBe(true)
    expect(fieldLoosens('epss_threshold', 0.3, null)).toBe(true)
    expect(fieldLoosens('epss_threshold', null, 0.9)).toBe(false)
    expect(fieldLoosens('baseline_grace_days', 30, 60)).toBe(true)
    expect(fieldLoosens('baseline_secrets_block', true, false)).toBe(true)
    expect(fieldLoosens('allow_repo_policy', false, true)).toBe(false)
    expect(fieldLoosens('modes', {}, { capabilities: { sast: 'comment' } })).toBe(true)
    expect(fieldLoosens('modes', { capabilities: { sast: 'monitor' } }, {})).toBe(false)
  })

  it('offers only stricter values for a locked field', () => {
    expect(allowedOptions('fail_on_severity', 'high', true)).toEqual(['low', 'medium', 'high'])
    expect(allowedOptions('fail_on_severity', 'high', false)).toHaveLength(5)
    expect(allowedOptions('mode', 'enforce', true)).toEqual(['enforce'])
    expect(allowedOptions('fail_on_kev', true, true)).toEqual([true])
    expect(allowedCapabilityModes({ capabilities: { sca: 'comment' } }, 'sca', true)).toEqual([
      'block',
      'comment',
    ])
    expect(allowedCapabilityModes({}, 'sast', true)).toEqual(['block'])
  })

  it('creates a repository policy that sets only the overridden field', () => {
    const w = overrideWrite(REPO, undefined, fieldsFixture(), 'mode', 'warn', {
      reason: 'Migration in progress for two weeks',
    })
    expect(w.id).toBeUndefined()
    expect(w.body).toMatchObject({
      scope_type: 'repository',
      scope_id: REPO,
      fields: ['mode'],
      mode: 'warn',
      fail_on_severity: 'high',
      reason: 'Migration in progress for two weeks',
    })
  })

  it('patches with every replaced value kept (reason, end date, EPSS, grace days)', () => {
    const w = overrideWrite(REPO, repoPolicy, [], 'mode', 'warn', {
      reason: repoPolicy.reason,
      expiresAt: repoPolicy.expires_at,
    })
    expect(w.id).toBe('pol-repo')
    expect(w.body.fields).toEqual(['mode', 'fail_on_severity', 'new_findings_only'])
    expect(w.body).toMatchObject({
      mode: 'warn',
      epss_threshold: 0.4,
      baseline_grace_days: 30,
      reason: repoPolicy.reason,
      expires_at: repoPolicy.expires_at,
    })
    expect(w.body.scope_type).toBeUndefined()
  })

  it('resets a field by removing it from fields, and deletes the policy with the last one', () => {
    const w = resetWrite(repoPolicy, 'new_findings_only', { reason: repoPolicy.reason })
    expect(w).toMatchObject({ kind: 'patch', id: 'pol-repo' })
    if (w.kind === 'patch') {
      expect(w.body.fields).toEqual(['fail_on_severity'])
      expect(w.body.baseline_grace_days).toBe(30)
    }
    expect(resetWrite({ ...repoPolicy, fields: ['mode'] }, 'mode', {})).toEqual({
      kind: 'delete',
      id: 'pol-repo',
    })
  })

  it('validates reason and end date bounds', () => {
    expect(validReason('too short')).toBe(false)
    expect(validReason('long enough reason')).toBe(true)
    expect(validReason('x'.repeat(501))).toBe(false)
    const now = new Date('2026-10-15T00:00:00Z')
    expect(validEndDate('', now)).toBe(true)
    expect(validEndDate('2026-12-01', now)).toBe(true)
    expect(validEndDate('2027-12-01', now)).toBe(false)
    expect(validEndDate('2026-10-01', now)).toBe(false)
  })

  it('passes the has-overrides filter to the pipelines API', () => {
    expect(pipelinesURL('/api/v1/ci', { hasPolicyOverride: true })).toContain(
      'has_policy_override=true'
    )
    expect(pipelinesURL('/api/v1/ci', {})).not.toContain('has_policy_override')
  })

  it('splits baseline and new findings only when a baseline is recorded', () => {
    expect(
      baselineCounts({
        summary: { new: 2, pre_existing: 7 },
        baseline: { set_at: '2026-10-01T00:00:00Z' },
      })
    ).toEqual({ baseline: 7, fresh: 2 })
    expect(baselineCounts({ summary: { new: 2, pre_existing: 7 }, baseline: {} })).toBeNull()
    expect(baselineDueAt('2026-10-01T00:00:00Z', 10)?.toISOString()).toBe(
      '2026-10-11T00:00:00.000Z'
    )
    expect(baselineDueAt('2026-10-01T00:00:00Z', null)).toBeNull()
  })

  it('labels retries of one commit as attempts', () => {
    const a = runAttempts([
      { id: 'r3', pipeline_id: 'p', commit_sha: 'abc', created_at: '2026-10-03' },
      { id: 'r1', pipeline_id: 'p', commit_sha: 'abc', created_at: '2026-10-01' },
      { id: 'r2', pipeline_id: 'p', commit_sha: 'def', created_at: '2026-10-02' },
    ])
    expect(a.get('r1')).toEqual({ attempt: 1, of: 2 })
    expect(a.get('r3')).toEqual({ attempt: 2, of: 2 })
    expect(a.has('r2')).toBe(false)
  })

  it('recognises a missing code-host connection and a reason request', () => {
    expect(missingCodeHost('no GitLab connection for this group')).toBe('gitlab')
    expect(missingCodeHost('no GitHub App installation for acme')).toBe('github')
    expect(missingCodeHost('rate limited')).toBeNull()
    expect(
      needsReasonError('a change that loosens the gate (mode) needs a reason of at least 10')
    ).toBe(true)
  })

  it('keeps the drawer tab from the URL', () => {
    expect(pipelineTab('settings')).toBe('settings')
    expect(pipelineTab('nope')).toBe('overview')
  })
})

// ── Settings tab ───────────────────────────────────────────

describe('CIRepositorySettingsTab', () => {
  it('shows each field with its source, lock, ignored marker and the inherited value', () => {
    render(<CIRepositorySettingsTab repositoryAssetId={REPO} />)
    const sev = document.querySelector('[data-field="fail_on_severity"]') as HTMLElement
    expect(within(sev).getByText('Organization')).toBeInTheDocument()
    expect(within(sev).getByText('Locked by organization')).toBeInTheDocument()
    expect(within(sev).getByText('Ignored (locked)')).toBeInTheDocument()
    const own = document.querySelector('[data-field="new_findings_only"]') as HTMLElement
    expect(own.dataset.source).toBe('repository')
    expect(within(own).getByText('This repository')).toBeInTheDocument()
    expect(within(own).getByText('Inherited: Off')).toBeInTheDocument()
    const kev = document.querySelector('[data-field="fail_on_kev"]') as HTMLElement
    expect(within(kev).getByText('Default')).toBeInTheDocument()
    expect(screen.getByText('Reason: Legacy service, retiring in Q1')).toBeInTheDocument()
  })

  it('is read only without the gate policy permission', () => {
    perms = ['scans:ci:read']
    render(<CIRepositorySettingsTab repositoryAssetId={REPO} />)
    expect(screen.queryByRole('button', { name: 'Override' })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /record baseline/i })).not.toBeInTheDocument()
    expect(screen.getByText(/Read only/)).toBeInTheDocument()
  })

  it('resets a field: it leaves fields and a loosening reset needs a reason', async () => {
    const user = userEvent.setup()
    render(<CIRepositorySettingsTab repositoryAssetId={REPO} />)
    await user.click(screen.getByRole('button', { name: 'Reset New findings only to inherited' }))
    const dialog = screen.getByRole('dialog')
    // new_findings_only true -> false is stricter: no reason needed.
    expect(within(dialog).getByText('Reason (optional)')).toBeInTheDocument()
    await user.click(within(dialog).getByRole('button', { name: 'Reset to inherited' }))
    expect(mockSave).toHaveBeenCalledTimes(1)
    const arg = mockSave.mock.calls[0][0]
    expect(arg.id).toBe('pol-repo')
    expect(arg.body.fields).toEqual(['fail_on_severity'])
    expect(arg.body.reason).toBe(repoPolicy.reason)
  })

  it('shows the baseline with its due date', () => {
    baseline = {
      repository_asset_id: REPO,
      source: 'first_run',
      branch: 'main',
      findings_count: 42,
      set_at: '2026-10-01T00:00:00Z',
    }
    settings = {
      ...(settings as object),
      fields: [
        ...fieldsFixture(),
        { field: 'baseline_grace_days', value: 10, inherited: 10, source: 'tenant' },
      ],
    }
    render(<CIRepositorySettingsTab repositoryAssetId={REPO} />)
    expect(screen.getByText('First verified default-branch run')).toBeInTheDocument()
    expect(screen.getByText('42')).toBeInTheDocument()
    expect(
      screen.getByText(new Date('2026-10-11T00:00:00Z').toLocaleDateString())
    ).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Remove baseline' })).toBeInTheDocument()
  })
})

// ── org policy locks ───────────────────────────────────────

describe('PolicyLocks', () => {
  it('toggles a lock and links the override count to the filtered pipelines', async () => {
    const user = userEvent.setup()
    const onChange = vi.fn()
    render(
      <PolicyLocks
        scopeType="tenant"
        locked={['mode']}
        onChange={onChange}
        overrideCounts={{ fail_on_severity: 3 }}
      />
    )
    expect(screen.getByTestId('override-count-fail_on_severity')).toHaveAttribute(
      'href',
      '/ci-cd?overrides=1'
    )
    expect(screen.getByText('3 repositories override this')).toBeInTheDocument()
    await user.click(screen.getByRole('switch', { name: 'Lock Mode' }))
    expect(onChange).toHaveBeenCalledWith([])
  })
})

// ── run drawer ─────────────────────────────────────────────

describe('CIRunSheet baseline and code host', () => {
  it('splits baseline and new findings, announces a new baseline and offers Connect GitLab', () => {
    perms = ['scans:ci:read', 'scans:ci:write']
    runDetail = {
      id: 'r1',
      repository: 'gitlab.com/acme/api',
      verdict: 'pass',
      decoration_state: 'skipped',
      decoration_detail: 'no GitLab connection for this group',
      verdict_detail: {
        summary: { evaluated: 9, new: 2, pre_existing: 7, accepted: 0, blocking: 0 },
        baseline: {
          branch: 'main',
          known: true,
          set_at: '2026-10-15T00:00:00Z',
          established: true,
          due_at: '2026-11-14T00:00:00Z',
        },
      },
    }
    render(<CIRunSheet id="r1" onClose={() => {}} />)
    expect(screen.getByTestId('ci-run-baseline-counts')).toHaveTextContent(
      '7 baseline (not blocking) · 2 new'
    )
    expect(screen.getByTestId('ci-run-baseline-established')).toHaveTextContent(
      'First run: 7 existing findings recorded as the baseline'
    )
    expect(screen.getByTestId('ci-run-connect-host')).toHaveAttribute(
      'href',
      '/ci-cd?tab=setup&section=feedback'
    )
  })

  it('hides Connect GitLab from a reader and has no baseline line without a baseline', () => {
    perms = ['scans:ci:read']
    runDetail = {
      id: 'r1',
      verdict: 'pass',
      decoration_state: 'skipped',
      decoration_detail: 'no GitLab connection for this group',
      verdict_detail: { summary: { new: 1, pre_existing: 3 }, baseline: { branch: 'main' } },
    }
    render(<CIRunSheet id="r1" onClose={() => {}} />)
    expect(screen.queryByTestId('ci-run-connect-host')).not.toBeInTheDocument()
    expect(screen.queryByTestId('ci-run-baseline-counts')).not.toBeInTheDocument()
  })
})
