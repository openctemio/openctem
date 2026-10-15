import { describe, expect, it, vi, beforeEach } from 'vitest'
import { renderHook } from '@testing-library/react'

const state = { module: true, perms: new Set<string>() }

vi.mock('@/features/integrations/api/use-tenant-modules', () => ({
  useModuleEnabled: () => state.module,
}))
vi.mock('@/context/permission-provider', () => ({
  usePermissions: () => ({ hasPermission: (p: string) => state.perms.has(p) }),
}))

import { useCanCreateTicket } from '../use-can-create-ticket'

describe('useCanCreateTicket', () => {
  beforeEach(() => {
    state.module = true
    state.perms = new Set()
  })
  it('needs findings:write, the gate of POST /findings/{id}/create-ticket', () => {
    expect(renderHook(() => useCanCreateTicket()).result.current).toBe(false)
    state.perms.add('findings:write')
    expect(renderHook(() => useCanCreateTicket()).result.current).toBe(true)
  })
  it('needs the integrations module', () => {
    state.perms.add('findings:write')
    state.module = false
    expect(renderHook(() => useCanCreateTicket()).result.current).toBe(false)
  })
})
