/**
 * Switching organization on "Findings, page 5, filtered" must not leave the
 * old organization's page, address or cached rows: the tree under the
 * boundary is unmounted, the address goes to the list root, and the page
 * mounts again with a fresh data cache.
 */
import * as React from 'react'
import { act, render, screen, waitFor } from '@testing-library/react'
import useSWR from 'swr'
import { beforeEach, describe, expect, it, vi } from 'vitest'

const nav = vi.hoisted(() => ({ pathname: '/findings', search: '' }))
// The router reports the new address on a later render, as Next.js does.
const replace = vi.fn()
function applyReplace() {
  const url = replace.mock.calls.at(-1)?.[0] as string
  const [p, q = ''] = url.split('?')
  nav.pathname = p
  nav.search = q
}
vi.mock('next/navigation', () => ({
  useRouter: () => ({ replace }),
  usePathname: () => nav.pathname,
  useSearchParams: () => new URLSearchParams(nav.search),
}))

const tenant = vi.hoisted(() => ({
  epoch: 0,
  epochKeepsLocation: false,
  org: 'A',
  currentTenant: { id: 'org-A' },
}))
vi.mock('@/context/tenant-provider', () => ({ useTenant: () => tenant }))

import { TenantEpochBoundary, takeSwitchLanding } from '../tenant-epoch-boundary'
import { mutate } from '@/lib/swr-mutate'
import { noteRendered, resetTenantEpochForTests } from '@/lib/tenant-epoch'

const fetched: string[] = []
let mounts = 0

/** A page of findings: reads the list for the address it is on. */
function FindingsPage() {
  React.useEffect(() => {
    mounts++
  }, [])
  const key = `/api/v1/findings?${nav.search}`
  const { data } = useSWR(key, async (k: string) => {
    fetched.push(`${tenant.org} ${k}`)
    return `rows of ${tenant.org}`
  })
  return <p data-testid="rows">{data ?? 'loading'}</p>
}

function Shell({ epoch }: { epoch: number }) {
  return (
    <TenantEpochBoundary key="boundary">
      <FindingsPage key={epoch === -1 ? 'never' : 'page'} />
    </TenantEpochBoundary>
  )
}

function switchTo(org: string, opts: { keepLocation?: boolean } = {}) {
  tenant.org = org
  tenant.currentTenant = { id: `org-${org}` }
  tenant.epoch += 1
  tenant.epochKeepsLocation = opts.keepLocation === true
}

beforeEach(() => {
  resetTenantEpochForTests()
  replace.mockClear()
  fetched.length = 0
  mounts = 0
  nav.pathname = '/findings'
  nav.search = 'page=5&severity=critical'
  tenant.epoch = 0
  tenant.epochKeepsLocation = false
  tenant.org = 'A'
  tenant.currentTenant = { id: 'org-A' }
})

describe('TenantEpochBoundary', () => {
  it('lands on the list root and mounts the page again with a fresh cache', async () => {
    const view = render(<Shell epoch={tenant.epoch} />)
    await waitFor(() => expect(screen.getByTestId('rows')).toHaveTextContent('rows of A'))
    expect(mounts).toBe(1)

    switchTo('B')
    view.rerender(<Shell epoch={tenant.epoch} />)

    // The old page is gone at once: no row of A is on screen while leaving.
    expect(screen.queryByTestId('rows')).toBeNull()
    expect(screen.getByTestId('org-switch-pending')).toBeInTheDocument()
    await waitFor(() => expect(replace).toHaveBeenCalledWith('/findings', { scroll: false }))
    // Until the router reports the landing, the old page stays unmounted.
    view.rerender(<Shell epoch={tenant.epoch} />)
    expect(screen.queryByTestId('rows')).toBeNull()
    expect(replace).toHaveBeenCalledTimes(1)
    applyReplace()
    view.rerender(<Shell epoch={tenant.epoch} />)

    await waitFor(() => expect(screen.getByTestId('rows')).toHaveTextContent('rows of B'))
    expect(mounts).toBe(2)
    // B's page read page 1 without A's filters; nothing was read with A's query under B.
    expect(fetched).toEqual(['A /api/v1/findings?page=5&severity=critical', 'B /api/v1/findings?'])
    expect(takeSwitchLanding('/findings')).toBe(true)
  })

  it('a detail page of the old organization goes to its section', async () => {
    nav.pathname = '/findings/0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b'
    nav.search = ''
    const view = render(<Shell epoch={tenant.epoch} />)
    await waitFor(() => expect(screen.getByTestId('rows')).toBeInTheDocument())
    switchTo('B')
    view.rerender(<Shell epoch={tenant.epoch} />)
    await waitFor(() => expect(replace).toHaveBeenCalledWith('/findings', { scroll: false }))
  })

  it('keeps the address when the switch was asked for by a link naming the organization', async () => {
    nav.pathname = '/findings/0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b'
    nav.search = 'org=org-b'
    const view = render(<Shell epoch={tenant.epoch} />)
    await waitFor(() => expect(screen.getByTestId('rows')).toHaveTextContent('rows of A'))
    switchTo('B', { keepLocation: true })
    view.rerender(<Shell epoch={tenant.epoch} />)
    await waitFor(() => expect(screen.getByTestId('rows')).toHaveTextContent('rows of B'))
    expect(replace).not.toHaveBeenCalled()
    expect(mounts).toBe(2)
  })

  it('stays on a list root without a query and still remounts with a fresh cache', async () => {
    nav.search = ''
    const view = render(<Shell epoch={tenant.epoch} />)
    await waitFor(() => expect(screen.getByTestId('rows')).toHaveTextContent('rows of A'))
    switchTo('B')
    view.rerender(<Shell epoch={tenant.epoch} />)
    await waitFor(() => expect(screen.getByTestId('rows')).toHaveTextContent('rows of B'))
    expect(replace).not.toHaveBeenCalled()
    expect(mounts).toBe(2)
  })

  it('the back button cannot reopen the old organization page', async () => {
    const view = render(<Shell epoch={tenant.epoch} />)
    await waitFor(() => expect(screen.getByTestId('rows')).toHaveTextContent('rows of A'))
    switchTo('B')
    view.rerender(<Shell epoch={tenant.epoch} />)
    await waitFor(() => expect(replace).toHaveBeenCalledTimes(1))
    applyReplace()
    view.rerender(<Shell epoch={tenant.epoch} />)
    await waitFor(() => expect(screen.getByTestId('rows')).toHaveTextContent('rows of B'))
    replace.mockClear()

    // Back: the browser returns to A's "page 5, critical".
    nav.pathname = '/findings'
    nav.search = 'page=5&severity=critical'
    window.history.replaceState(null, '', '/findings?page=5&severity=critical')
    act(() => {
      window.dispatchEvent(new PopStateEvent('popstate'))
    })
    view.rerender(<Shell epoch={tenant.epoch} />)
    expect(screen.queryByText('rows of A')).toBeNull()
    await waitFor(() => expect(replace).toHaveBeenCalledWith('/findings', { scroll: false }))
  })

  it('a document the back button loaded on the old organization page lands on the list root', async () => {
    // The tab showed A's page 5, then switched to B; the back button loads
    // that address as a new document under B's session.
    noteRendered('/findings?page=5&severity=critical', 'org-A')
    tenant.currentTenant = { id: 'org-B' }
    const nav = vi
      .spyOn(performance, 'getEntriesByType')
      .mockReturnValue([{ type: 'back_forward' } as unknown as PerformanceEntry])
    window.history.replaceState(null, '', '/findings?page=5&severity=critical')
    render(<Shell epoch={tenant.epoch} />)
    await waitFor(() => expect(replace).toHaveBeenCalledWith('/findings', { scroll: false }))
    expect(screen.queryByText('rows of A')).toBeNull()
    nav.mockRestore()
  })

  it('a page that suspends never leaves a reader without its cache (crash seen after Back)', async () => {
    nav.search = ''
    const never = new Promise(() => {})
    function Suspender({ on }: { on: boolean }) {
      if (on) throw never
      return null
    }
    function Page({ on, tick }: { on: boolean; tick: number }) {
      return (
        <React.Suspense fallback={<p>app loading</p>}>
          <TenantEpochBoundary>
            <Suspender on={on} />
            <FindingsPage key={tick === -1 ? 'x' : 'page'} />
          </TenantEpochBoundary>
        </React.Suspense>
      )
    }
    const errors: unknown[] = []
    const onErr = (e: ErrorEvent) => errors.push(e.error)
    window.addEventListener('error', onErr)
    const view = render(<Page on={false} tick={0} />)
    await waitFor(() => expect(screen.getByTestId('rows')).toHaveTextContent('rows of A'))
    // An urgent update makes a page part suspend, then the tree renders again.
    await act(async () => view.rerender(<Page on={true} tick={1} />))
    await act(async () => view.rerender(<Page on={true} tick={2} />))
    await act(async () => view.rerender(<Page on={false} tick={3} />))
    window.removeEventListener('error', onErr)
    expect(errors).toEqual([])
    expect(screen.getByTestId('rows')).toHaveTextContent('rows of A')
  })

  it('module-level mutate reaches the current epoch cache', async () => {
    nav.search = ''
    const view = render(<Shell epoch={tenant.epoch} />)
    await waitFor(() => expect(screen.getByTestId('rows')).toHaveTextContent('rows of A'))
    switchTo('B')
    view.rerender(<Shell epoch={tenant.epoch} />)
    await waitFor(() => expect(screen.getByTestId('rows')).toHaveTextContent('rows of B'))
    await act(async () => {
      await mutate('/api/v1/findings?', 'patched in B', { revalidate: false })
    })
    expect(screen.getByTestId('rows')).toHaveTextContent('patched in B')
  })
})
