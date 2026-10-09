/**
 * The dashboard's widgets read the overview's answers (one request) instead
 * of each asking its endpoint (research/81).
 */
import * as React from 'react'
import { render, screen, waitFor } from '@testing-library/react'
import useSWR, { SWRConfig } from 'swr'
import { beforeEach, describe, expect, it, vi } from 'vitest'

const get = vi.fn()
vi.mock('@/lib/api/client', () => ({ get: (...a: unknown[]) => get(...a) }))
vi.mock('@/context/tenant-provider', () => ({ useTenant: () => ({ currentTenant: { id: 't1' } }) }))
let bootstrapPending = false
vi.mock('@/context/bootstrap-provider', () => ({ useBootstrapPending: () => bootstrapPending }))
vi.mock('@/lib/permissions', async (orig) => ({
  ...(await orig<typeof import('@/lib/permissions')>()),
  usePermissions: () => ({ can: () => true }),
}))

import {
  DASHBOARD_OVERVIEW_URL,
  DashboardOverviewProvider,
  overviewFallback,
} from '../dashboard-overview'

function Widget({ url }: { url: string }) {
  const { data } = useSWR<{ n: number }>(url, (u: string) => get(u))
  return <span data-testid={url}>{data ? String(data.n) : 'loading'}</span>
}

function renderDashboard() {
  return render(
    <SWRConfig value={{ provider: () => new Map(), dedupingInterval: 0 }}>
      <DashboardOverviewProvider loading={<span>skeleton</span>}>
        <Widget url="/api/v1/dashboard/stats" />
        <Widget url="/api/v1/attack-surface/attack-paths" />
      </DashboardOverviewProvider>
    </SWRConfig>
  )
}

describe('DashboardOverviewProvider', () => {
  beforeEach(() => {
    get.mockReset()
    bootstrapPending = false
  })

  it('renders nothing and asks nothing while the session is still loading', () => {
    bootstrapPending = true
    renderDashboard()
    expect(screen.getByText('skeleton')).toBeInTheDocument()
    expect(get).not.toHaveBeenCalled()
  })

  it('one request feeds every widget whose part came back', async () => {
    get.mockImplementation(async (url: string) => {
      if (url === DASHBOARD_OVERVIEW_URL)
        return {
          parts: {
            '/api/v1/dashboard/stats': { status: 200, body: { n: 7 } },
            '/api/v1/attack-surface/attack-paths': { status: 200, body: { n: 3 } },
          },
        }
      throw new Error(`unexpected ${url}`)
    })
    renderDashboard()
    await waitFor(() =>
      expect(screen.getByTestId('/api/v1/dashboard/stats')).toHaveTextContent('7')
    )
    expect(screen.getByTestId('/api/v1/attack-surface/attack-paths')).toHaveTextContent('3')
    expect(get).toHaveBeenCalledTimes(1)
  })

  it('a part the caller may not read is asked by its own widget, as before', async () => {
    get.mockImplementation(async (url: string) => {
      if (url === DASHBOARD_OVERVIEW_URL)
        return {
          parts: {
            '/api/v1/dashboard/stats': { status: 200, body: { n: 7 } },
            '/api/v1/attack-surface/attack-paths': { status: 403 },
          },
        }
      return { n: 1 }
    })
    renderDashboard()
    await waitFor(() => expect(get).toHaveBeenCalledWith('/api/v1/attack-surface/attack-paths'))
    expect(get).not.toHaveBeenCalledWith('/api/v1/dashboard/stats')
  })

  it('shows the skeleton, and no widget asks, until the overview settles', () => {
    get.mockImplementation(() => new Promise(() => {}))
    renderDashboard()
    expect(screen.getByText('skeleton')).toBeInTheDocument()
    expect(get).toHaveBeenCalledTimes(1)
  })

  it('without the overview (an older API) every widget asks its own endpoint', async () => {
    get.mockImplementation(async (url: string) => {
      if (url === DASHBOARD_OVERVIEW_URL) throw Object.assign(new Error('nf'), { statusCode: 404 })
      return { n: 2 }
    })
    renderDashboard()
    await waitFor(() =>
      expect(screen.getByTestId('/api/v1/dashboard/stats')).toHaveTextContent('2')
    )
  })

  it('hands over only successful parts', () => {
    expect(
      overviewFallback({
        parts: { a: { status: 200, body: 1 }, b: { status: 403 }, c: { status: 200 } },
      })
    ).toEqual({ a: 1 })
  })
})
