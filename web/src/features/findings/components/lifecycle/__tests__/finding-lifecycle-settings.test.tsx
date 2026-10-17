import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen } from '@testing-library/react'

let canWrite = false
const fetched: string[] = []

vi.mock('@/lib/permissions', () => ({
  Permission: { FindingsLifecyclesWrite: 'findings:lifecycles:write' },
  usePermissions: () => ({ can: () => canWrite }),
}))
vi.mock('@/context/tenant-provider', () => ({
  useTenant: () => ({ currentTenant: { id: 't1', name: 'ORG' } }),
}))
vi.mock('@/lib/api/client', () => {
  const get = async (url: string) => {
    fetched.push(url)
    if (url.startsWith('/api/v1/lifecycle-sub-statuses')) return { data: [], colors: ['gray'] }
    if (url.startsWith('/api/v1/organization/limits'))
      return {
        limits: [
          { key: 'lifecycle_sub_statuses', limit: 3, used: 3 },
          { key: 'lifecycle_schemes', limit: 0, used: 0 },
        ],
      }
    return { data: [] }
  }
  return { get, fetcher: get, post: vi.fn(), put: vi.fn(), patch: vi.fn(), del: vi.fn() }
})

import { FindingLifecycleSettings } from '../finding-lifecycle-settings'

if (!('ResizeObserver' in globalThis)) {
  ;(globalThis as { ResizeObserver?: unknown }).ResizeObserver = class {
    observe() {}
    unobserve() {}
    disconnect() {}
  }
}

describe('FindingLifecycleSettings gating', () => {
  beforeEach(() => {
    fetched.length = 0
  })

  it('shows a read-only notice and never asks for the limits without the write permission', async () => {
    canWrite = false
    render(<FindingLifecycleSettings />)
    expect(await screen.findByText(/you can see the lifecycle/i)).toBeInTheDocument()
    expect(fetched.some((u) => u.startsWith('/api/v1/organization/limits'))).toBe(false)
  })

  it('shows the limit usage and the limit state to someone who may change it', async () => {
    canWrite = true
    render(<FindingLifecycleSettings />)
    expect(await screen.findByText(/3 of 3 used/i)).toBeInTheDocument()
    expect(screen.getByText(/limit of sub-statuses/i)).toBeInTheDocument()
    expect(screen.queryByText(/you can see the lifecycle/i)).not.toBeInTheDocument()
  })
})
