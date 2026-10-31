/**
 * Attack surface posture: the overview card and the Posture page render the
 * grade, the categories, the fix plan (assets link to their page), the risk
 * reduction and the root domains; Recalculate now maps 429 to its own
 * message and is hidden without assets:write; the schedule needs
 * settings:write; nothing is fetched without assets:read; the CSV is
 * formula safe.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { SWRConfig } from 'swr'
import type { ReactNode } from 'react'

const api = vi.hoisted(() => ({ get: vi.fn(), post: vi.fn(), put: vi.fn() }))
vi.mock('@/lib/api/client', () => api)
const toast = vi.hoisted(() => ({ success: vi.fn(), error: vi.fn() }))
vi.mock('sonner', () => ({ toast }))
const perms = vi.hoisted(() => ({ granted: new Set<string>(['assets:read', 'assets:write']) }))
vi.mock('@/lib/permissions', async (orig) => {
  const actual = await orig<typeof import('@/lib/permissions')>()
  return { ...actual, usePermissions: () => ({ can: (p: string) => perms.granted.has(p) }) }
})

const { EASMPosture } = await import('../easm-posture')
const { EASMPostureCard } = await import('../easm-posture-card')
const { rootsCsv, topDeductions, scoreDelta, postureUrl } = await import('../../lib/posture')

const wrap = (ui: ReactNode) =>
  render(<SWRConfig value={{ provider: () => new Map(), dedupingInterval: 0 }}>{ui}</SWRConfig>)

const cats = [
  {
    category: 'vulnerabilities',
    max: 35,
    points: 30,
    issues: 4,
    deduction: 8.4,
    score_if_fixed: 90,
    grade_if_fixed: 'A',
  },
  {
    category: 'hijackable_subdomains',
    max: 15,
    points: 10,
    issues: 1,
    deduction: 5,
    score_if_fixed: 86,
    grade_if_fixed: 'B',
  },
  { category: 'exposed_services', max: 15, points: 0, issues: 0, deduction: 0 },
  { category: 'cloud_storage', max: 10, points: 0, issues: 0, deduction: 0 },
  { category: 'misconfiguration', max: 15, points: 2, issues: 1, deduction: 0.4 },
  { category: 'suspicious_activity', max: 10, points: 0, issues: 0, deduction: 0 },
]

const body = (over: Record<string, unknown> = {}) => ({
  state: {
    refresh_every: '6h',
    computed_at: '2026-10-31T08:00:00Z',
    building: false,
    stale: false,
  },
  scoped: false,
  filtered: false,
  score: { measured: true, score: 81, grade: 'B', assets: 40, categories: cats },
  previous_score: 78,
  previous_grade: 'C',
  plan: {
    target: 'A',
    floor: 90,
    reached: true,
    steps: [
      {
        asset_id: '0196f0c2-1111-7000-8000-000000000001',
        asset_name: 'shop.example.com',
        category: 'hijackable_subdomains',
        points: 10,
        issues: 1,
        score_after: 86,
        grade_after: 'B',
      },
      { category: 'suspicious_activity', points: 2, issues: 1, score_after: 90, grade_after: 'A' },
    ],
  },
  reductions: [
    { criticality: 'critical', assets: 2, issues: 3, points: 30, share: 71.4, gain: 9.1 },
    { criticality: 'high', assets: 0, issues: 0, points: 0, share: 0, gain: 0 },
    { criticality: 'medium', assets: 38, issues: 3, points: 12, share: 28.6, gain: 3.2 },
    { criticality: 'low', assets: 0, issues: 0, points: 0, share: 0, gain: 0 },
  ],
  roots: [
    {
      root_domain: 'example.com',
      score: 74,
      grade: 'C',
      assets: 30,
      issues: 5,
      top_category: 'vulnerabilities',
    },
    { root_domain: 'example.org', score: 95, grade: 'A', assets: 10, issues: 1 },
  ],
  roots_total: 2,
  ...over,
})

beforeEach(() => {
  vi.clearAllMocks()
  perms.granted = new Set(['assets:read', 'assets:write'])
  api.get.mockResolvedValue(body())
})

describe('EASMPostureCard', () => {
  it('shows the grade, the change and the top categories, linking to the page', async () => {
    wrap(<EASMPostureCard />)
    expect(await screen.findByTestId('posture-score')).toHaveTextContent('81')
    expect(screen.getByRole('img', { name: /Grade B, score 81/ })).toBeInTheDocument()
    expect(screen.getByText('Up 3 since the last computation')).toBeInTheDocument()
    expect(screen.getByText('Fix 2 items to reach A (90).')).toBeInTheDocument()
    // Only the categories that take points, largest first.
    const items = document.querySelectorAll('[data-category]')
    expect([...items].map((e) => e.getAttribute('data-category'))).toEqual([
      'vulnerabilities',
      'hijackable_subdomains',
      'misconfiguration',
    ])
    expect(screen.getByRole('link', { name: 'What to fix to raise the grade' })).toHaveAttribute(
      'href',
      '/attack-surface/posture'
    )
  })

  it('says when the first computation is still running', async () => {
    api.get.mockResolvedValue(
      body({
        state: { refresh_every: '6h', building: true, stale: false },
        score: { measured: false, score: 0, assets: 0, categories: [] },
      })
    )
    wrap(<EASMPostureCard />)
    expect(await screen.findByTestId('posture-building')).toBeInTheDocument()
  })

  it('fetches nothing without assets:read', () => {
    perms.granted = new Set()
    wrap(<EASMPostureCard />)
    expect(api.get).not.toHaveBeenCalled()
  })
})

describe('EASMPosture', () => {
  it('renders the plan with asset links, the reductions and the roots', async () => {
    wrap(<EASMPosture />)
    expect(await screen.findByTestId('posture-plan')).toBeInTheDocument()
    expect(screen.getByRole('link', { name: 'shop.example.com' })).toHaveAttribute(
      'href',
      '/assets/0196f0c2-1111-7000-8000-000000000001'
    )
    expect(screen.getByText('Issues without an asset')).toBeInTheDocument()
    expect(screen.getByText('+9.1')).toBeInTheDocument()
    expect(screen.getByText('fixed: 90 (A)')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'example.com' })).toBeInTheDocument()
  })

  it('opens one root domain through the API filter', async () => {
    wrap(<EASMPosture />)
    await userEvent.click(await screen.findByRole('button', { name: 'example.com' }))
    await waitFor(() =>
      expect(api.get).toHaveBeenCalledWith('/api/v1/attack-surface/posture?root_domain=example.com')
    )
  })

  it('maps a 429 on Recalculate now to its own message', async () => {
    api.post.mockRejectedValue({ statusCode: 429 })
    wrap(<EASMPosture />)
    await userEvent.click(await screen.findByRole('button', { name: 'Recalculate now' }))
    await waitFor(() =>
      expect(toast.error).toHaveBeenCalledWith(
        'Recalculated less than five minutes ago. Try again later.'
      )
    )
    expect(api.post).toHaveBeenCalledWith('/api/v1/attack-surface/posture/refresh', {})
  })

  it('hides Recalculate without assets:write and the schedule without settings:write', async () => {
    perms.granted = new Set(['assets:read'])
    wrap(<EASMPosture />)
    await screen.findByTestId('posture-plan')
    expect(screen.queryByRole('button', { name: 'Recalculate now' })).not.toBeInTheDocument()
    expect(screen.queryByRole('combobox', { name: 'Refresh schedule' })).not.toBeInTheDocument()
  })

  it('shows the scoped title for a scoped reader', async () => {
    api.get.mockResolvedValue(body({ scoped: true, previous_score: undefined }))
    wrap(<EASMPosture />)
    expect(await screen.findByText('Posture of the assets you can see')).toBeInTheDocument()
  })
})

describe('posture helpers', () => {
  it('builds the root URL', () => {
    expect(postureUrl()).toBe('/api/v1/attack-surface/posture')
    expect(postureUrl('a b.com')).toBe('/api/v1/attack-surface/posture?root_domain=a+b.com')
  })

  it('orders deductions and computes the delta', () => {
    expect(topDeductions(cats, 2).map((c) => c.category)).toEqual([
      'vulnerabilities',
      'hijackable_subdomains',
    ])
    expect(
      scoreDelta({
        score: { measured: true, score: 81, assets: 1, categories: [] },
        previous_score: 78,
      })
    ).toBe(3)
    expect(
      scoreDelta({
        score: { measured: false, score: 0, assets: 0, categories: [] },
        previous_score: 78,
      })
    ).toBeNull()
  })

  it('neutralises formulas in the CSV', () => {
    const csv = rootsCsv(
      [{ root_domain: '=cmd.example', score: 50, grade: 'F', assets: 1, issues: 2 }],
      ['Root']
    )
    expect(csv.split('\n')[1]).toBe(`"'=cmd.example","F","50","1","2",""`)
  })
})
