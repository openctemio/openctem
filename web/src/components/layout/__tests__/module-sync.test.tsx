import { render } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { ModuleSync } from '../module-sync'

const refreshModules = vi.fn()
let onData: ((e: unknown) => void) | undefined
let channelTenant: string | null | undefined

vi.mock('@/context/tenant-provider', () => ({
  useTenant: () => ({ currentTenant: { id: 'tenant-a' } }),
}))
vi.mock('@/context/bootstrap-provider', () => ({
  useBootstrapContext: () => ({ refreshModules }),
}))
vi.mock('@/hooks/use-websocket', () => ({
  useTenantChannel: (tenantId: string | null, opts: { onData?: (e: unknown) => void }) => {
    channelTenant = tenantId
    onData = opts.onData
    return { data: null, isSubscribed: true, clearData: () => {} }
  },
}))

describe('ModuleSync', () => {
  beforeEach(() => {
    refreshModules.mockReset()
    onData = undefined
  })

  it('listens on the current organization channel', () => {
    render(<ModuleSync />)
    expect(channelTenant).toBe('tenant-a')
  })

  it('re-reads the modules on module.updated for this organization', () => {
    render(<ModuleSync />)
    onData?.({ type: 'module.updated', tenant_id: 'tenant-a', version: 3 })
    expect(refreshModules).toHaveBeenCalledTimes(1)
  })

  it('ignores other events and other organizations', () => {
    render(<ModuleSync />)
    onData?.({ type: 'scan.completed', tenant_id: 'tenant-a' })
    onData?.({ type: 'module.updated', tenant_id: 'tenant-b' })
    onData?.(null)
    expect(refreshModules).not.toHaveBeenCalled()
  })
})
