import { describe, expect, it, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

vi.mock('sonner', () => ({ toast: { success: vi.fn(), error: vi.fn() } }))
const trigger = vi.fn(async (_arg: unknown) => ({}))
vi.mock('../../api/use-verified-domains', () => ({
  useUpdateDomainJIT: () => ({ trigger, isMutating: false }),
}))

import { DomainJITDialog, jitLabel } from '../domain-jit-dialog'

const domain = {
  id: 'd1',
  domain: 'corp.example',
  status: 'verified' as const,
  created_at: '2026-10-01T00:00:00Z',
  jit_enabled: true,
  jit_role: 'member' as const,
}

describe('jitLabel', () => {
  it('describes the provisioning of a domain', () => {
    expect(jitLabel({ jit_enabled: false })).toBe('Not admitted')
    expect(jitLabel({ jit_enabled: true, jit_role: 'viewer' })).toBe('Join as Viewer')
    expect(jitLabel({})).toBe('Join with the IdP default')
  })
})

describe('DomainJITDialog', () => {
  it('turns provisioning off for a domain', async () => {
    const onSaved = vi.fn()
    render(
      <DomainJITDialog tenantId="t1" domain={domain} onOpenChange={vi.fn()} onSaved={onSaved} />
    )
    const user = userEvent.setup()
    await user.click(screen.getByLabelText('Admit new people'))
    await user.click(screen.getByRole('button', { name: 'Save' }))
    expect(trigger).toHaveBeenCalledWith({ id: 'd1', jit_enabled: false, jit_role: 'member' })
    expect(onSaved).toHaveBeenCalled()
  })
})
