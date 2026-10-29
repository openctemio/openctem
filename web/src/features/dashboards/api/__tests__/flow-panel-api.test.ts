import { beforeEach, describe, expect, it, vi } from 'vitest'

const http = vi.hoisted(() => ({ post: vi.fn(), del: vi.fn() }))
vi.mock('@/lib/api/client', () => ({
  get: vi.fn(),
  put: vi.fn(),
  post: http.post,
  del: http.del,
}))
vi.mock('@/context/tenant-provider', () => ({ useTenant: () => ({ currentTenant: null }) }))

import { addFlowPanel, undoFlowPanel } from '../use-dashboards-api'

describe('flow panel API', () => {
  beforeEach(() => vi.clearAllMocks())

  it('posts the add to the personal or organization route', async () => {
    await addFlowPanel('d1', 'personal')
    await addFlowPanel('o1', 'organization')
    expect(http.post).toHaveBeenNthCalledWith(1, '/api/v1/me/dashboards/d1/flow-panel', {})
    expect(http.post).toHaveBeenNthCalledWith(
      2,
      '/api/v1/organization/dashboards/o1/flow-panel',
      {}
    )
  })

  it('Undo calls the delete endpoint with the widget id', async () => {
    await undoFlowPanel('d1', 'personal', 'w_flow')
    await undoFlowPanel('o1', 'organization', 'w_flow2')
    expect(http.del).toHaveBeenNthCalledWith(1, '/api/v1/me/dashboards/d1/flow-panel/w_flow')
    expect(http.del).toHaveBeenNthCalledWith(
      2,
      '/api/v1/organization/dashboards/o1/flow-panel/w_flow2'
    )
  })
})
