import { beforeEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen } from '@testing-library/react'

const push = vi.fn()
vi.mock('next/navigation', () => ({ useRouter: () => ({ push }) }))
let perms = new Set<string>()
let modules: string[] = []
let canInvite = false
vi.mock('@/context/permission-provider', () => ({
  usePermissions: () => ({ hasPermission: (p: string) => perms.has(p) }),
}))
vi.mock('@/features/integrations/api/use-tenant-modules', () => ({
  useModuleEnabled: (id: string) => modules.includes(id),
}))
vi.mock('@/lib/permissions', async (orig) => ({
  ...(await orig<typeof import('@/lib/permissions')>()),
  useCanMutate: () => canInvite,
}))

import { HeaderCreateMenu } from '../header-create-menu'
import { TooltipProvider } from '@/components/ui/tooltip'

const open = () => {
  const trigger = screen.getByRole('button', { name: 'Create' })
  fireEvent.pointerDown(trigger, { button: 0, ctrlKey: false })
  return trigger
}
const items = () => screen.getAllByRole('menuitem').map((m) => m.getAttribute('data-create'))
const renderMenu = () =>
  render(
    <TooltipProvider>
      <HeaderCreateMenu />
    </TooltipProvider>
  )

beforeEach(() => {
  push.mockReset()
  perms = new Set()
  modules = []
  canInvite = false
})

describe('HeaderCreateMenu', () => {
  it('is not shown when the caller may create nothing', () => {
    renderMenu()
    expect(screen.queryByRole('button', { name: 'Create' })).toBeNull()
  })

  it('lists every action in order with its chord when everything is allowed', () => {
    perms = new Set([
      'scans:write',
      'findings:write',
      'findings:read',
      'assets:write',
      'assets:import',
      'findings:remediation:write',
    ])
    modules = ['scans', 'remediation']
    canInvite = true
    renderMenu()
    open()
    expect(items()).toEqual(['scan', 'import', 'asset', 'finding', 'task', 'invite'])
    const scan = screen.getByRole('menuitem', { name: /New scan/ })
    expect(scan.getAttribute('href')).toBe('/scans?new=scan')
    expect(scan.getAttribute('aria-keyshortcuts')).toBe('n s')
  })

  it('hides an action without its permission or its module', () => {
    perms = new Set(['scans:write', 'findings:remediation:write', 'findings:read', 'assets:write'])
    modules = [] // scans and remediation modules off
    renderMenu()
    open()
    expect(items()).toEqual(['asset'])
  })

  it('import needs all three permissions of the import route', () => {
    perms = new Set(['findings:write', 'assets:import'])
    renderMenu()
    open()
    expect(items()).toEqual(['finding'])
  })

  it('the chord runs only an allowed action', () => {
    perms = new Set(['assets:write'])
    renderMenu()
    const key = (k: string) =>
      document.body.dispatchEvent(
        new KeyboardEvent('keydown', { key: k, bubbles: true, cancelable: true })
      )
    key('n')
    key('s')
    expect(push).not.toHaveBeenCalled()
    key('n')
    key('a')
    expect(push).toHaveBeenCalledWith('/assets?new=asset')
  })
})
