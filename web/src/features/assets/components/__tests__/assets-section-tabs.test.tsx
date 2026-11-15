/**
 * Assets tabs: Needs attention carries how many assets wait for a scoping
 * decision (the kit's tab count, hidden at zero and while loading), named for
 * screen readers as "Needs attention, N assets waiting". The count is asked
 * only when the tab is visible, and sent only by the pages that send that
 * request anyway (inventory, Needs attention landing); the rest read the cache.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen } from '@testing-library/react'

const state = vi.hoisted(() => ({
  hidden: [] as string[],
  count: undefined as number | undefined,
  pathname: '/assets',
  calls: [] as [string, boolean | undefined, { cacheOnly?: boolean } | undefined][],
}))

vi.mock('next/navigation', () => ({ usePathname: () => state.pathname }))
vi.mock('next/link', () => ({
  default: ({ href, children, ...rest }: { href: string; children: React.ReactNode }) => (
    <a href={href} {...rest}>
      {children}
    </a>
  ),
  useLinkStatus: () => ({ pending: false }),
}))
vi.mock('@/lib/permissions', async (orig) => ({
  ...(await orig<typeof import('@/lib/permissions')>()),
  useVisibleSectionTabs: (rows: { href: string }[]) =>
    rows.filter((r) => !state.hidden.includes(r.href)),
}))
vi.mock('../attention/use-attention-count', () => ({
  useAttentionCount: (id: string, enabled?: boolean, opts?: { cacheOnly?: boolean }) => {
    state.calls.push([id, enabled, opts])
    return enabled === false ? undefined : state.count
  },
}))

import { AssetsSectionTabs } from '../assets-section-tabs'

beforeEach(() => {
  state.hidden = []
  state.count = undefined
  state.calls = []
  state.pathname = '/assets'
})

describe('AssetsSectionTabs', () => {
  it('shows the assets waiting for a decision beside Needs attention', () => {
    state.count = 462
    render(<AssetsSectionTabs />)
    const tab = screen.getByRole('link', { name: 'Needs attention, 462 assets waiting' })
    expect(tab).toHaveAttribute('href', '/assets/attention')
    expect(tab.querySelector('[data-slot=tabs-count]')).toHaveTextContent('462')
    expect(state.calls.every(([id]) => id === 'decide_monitoring')).toBe(true)
    // Only that tab has a count.
    const counted = screen
      .getAllByRole('link')
      .filter((a) => a.querySelector('[data-slot=tabs-count]'))
    expect(counted).toEqual([tab])
  })

  it('says "asset" for one', () => {
    state.count = 1
    render(<AssetsSectionTabs />)
    expect(screen.getByRole('link', { name: 'Needs attention, 1 asset waiting' })).toBeVisible()
  })

  it.each([
    ['zero', 0],
    ['loading', undefined],
  ])('shows no count and the plain label when %s', (_, count) => {
    state.count = count
    render(<AssetsSectionTabs />)
    const tab = screen.getByRole('link', { name: 'Needs attention' })
    expect(tab).not.toHaveAttribute('aria-label')
    expect(tab.querySelector('[data-slot=tabs-count]')).toBeNull()
  })

  it('asks for no count when Needs attention is not shown', () => {
    state.hidden = ['/assets/attention']
    state.count = 462
    render(<AssetsSectionTabs />)
    expect(screen.queryByRole('link', { name: /Needs attention/ })).toBeNull()
    expect(state.calls.length).toBeGreaterThan(0)
    expect(state.calls.every(([, enabled]) => enabled === false)).toBe(true)
  })

  it.each([
    ['/assets', false],
    ['/assets/attention', false],
    ['/assets/groups', true],
    ['/assets/changes', true],
    ['/assets/attention/no-owner', true],
  ])('on %s the count is cache only: %s', (path, cacheOnly) => {
    state.pathname = path
    render(<AssetsSectionTabs />)
    expect(state.calls.at(-1)).toEqual(['decide_monitoring', true, { cacheOnly }])
  })
})
