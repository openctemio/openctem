import { describe, expect, it, vi } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import { RoleTemplateUpdate } from '../role-template-update'
import type { Role } from '../../types/role.types'

const applyRoleTemplateUpdate = vi.hoisted(() => vi.fn())
vi.mock('../../api/use-roles', () => ({ applyRoleTemplateUpdate }))
vi.mock('swr', async (orig) => ({
  ...(await orig<typeof import('swr')>()),
  useSWRConfig: () => ({ mutate: vi.fn() }),
}))
vi.mock('@/lib/permissions', () => ({
  Can: ({ children }: { children: React.ReactNode }) => <>{children}</>,
  Permission: { RolesWrite: 'roles:write' },
}))
vi.mock('sonner', () => ({ toast: { success: vi.fn(), error: vi.fn() } }))

const role = {
  id: 'r1',
  name: 'Analyst',
  is_system: false,
  template: {
    template_id: 'tpl',
    template_name: 'Analyst template',
    version_taken: 1,
    current_version: 2,
    update_available: true,
    diff: { added: ['findings:write', 'scans:run'], removed: ['assets:delete'] },
  },
} as unknown as Role

describe('RoleTemplateUpdate', () => {
  it('asks before applying a template update to everyone holding the role', async () => {
    applyRoleTemplateUpdate.mockResolvedValue(role)
    render(<RoleTemplateUpdate role={role} />)
    await userEvent.click(screen.getByRole('button', { name: 'Apply update' }))
    const dialog = await screen.findByRole('alertdialog')
    expect(dialog).toHaveTextContent('Apply the template update to Analyst?')
    expect(dialog).toHaveTextContent('adds 2 permissions and removes 1')
    expect(applyRoleTemplateUpdate).not.toHaveBeenCalled()
    const buttons = screen.getAllByRole('button', { name: 'Apply update' })
    await userEvent.click(buttons[buttons.length - 1])
    await waitFor(() => expect(applyRoleTemplateUpdate).toHaveBeenCalledWith('r1', 2))
  })
})
