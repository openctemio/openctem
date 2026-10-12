import { renderHook } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'

const permissionModules = vi.fn()
const tenantModules = vi.fn()
vi.mock('../use-roles', () => ({ usePermissionModules: () => permissionModules() }))
vi.mock('@/features/integrations/api/use-tenant-modules', () => ({
  useTenantModules: () => tenantModules(),
}))

import { useTenantPermissionModules } from '../use-tenant-permissions'

const mod = (id: string) => ({ id, name: id, permissions: [{ id: id + ':read', name: 'read' }] })

describe('useTenantPermissionModules', () => {
  beforeEach(() => {
    permissionModules.mockReturnValue({
      modules: [
        mod('pentest'),
        mod('sla'),
        mod('remediation'),
        mod('scope_config'),
        mod('compliance'),
      ],
      isLoading: false,
      error: undefined,
    })
  })

  // The role editor used a hand-kept map to ids that do not exist
  // (validation, campaigns), so pentest, SLA and remediation permissions were
  // hidden even with their modules on.
  it('shows the permissions of every enabled module by its real id', () => {
    tenantModules.mockReturnValue({
      moduleIds: ['pentest', 'sla', 'remediation', 'scope_config'],
      isLoading: false,
    })
    const { result } = renderHook(() => useTenantPermissionModules())
    expect(result.current.modules.map((m) => m.id)).toEqual([
      'pentest',
      'sla',
      'remediation',
      'scope_config',
    ])
    expect(result.current.hiddenModulesCount).toBe(1)
  })

  it('shows everything while the module list is unknown', () => {
    tenantModules.mockReturnValue({ moduleIds: [], isLoading: false })
    const { result } = renderHook(() => useTenantPermissionModules())
    expect(result.current.modules).toHaveLength(5)
  })
})
