/**
 * A copy of a system template is offered the template's later changes; it
 * changes only when a person with workflow write applies them.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import { TemplateUpdateCard } from '../template-update-card'
import { Permission } from '@/lib/permissions'

let perms: string[] = []
vi.mock('@/lib/permissions/hooks', () => ({
  usePermissions: () => ({
    permissions: perms,
    can: (p: string) => perms.includes(p),
    canAny: (...p: string[]) => p.some((x) => perms.includes(x)),
    canAll: (...p: string[]) => p.every((x) => perms.includes(x)),
    isAtLeast: () => false,
    isLoading: false,
    tenantRole: 'member',
  }),
}))
vi.mock('sonner', () => ({ toast: { success: vi.fn(), error: vi.fn() } }))

const get = vi.fn()
const post = vi.fn()
vi.mock('@/lib/api/client', () => ({
  get: (...a: unknown[]) => get(...a),
  post: (...a: unknown[]) => post(...a),
}))

const update = {
  available: true,
  source_template_id: 'tpl',
  source_template_name: 'Network',
  template_digest: 'd1',
  changes: [
    {
      kind: 'add_step',
      step_key: 'hosts',
      name: 'Host discovery',
      capabilities: ['discover.hosts'],
      depends_on: [],
    },
    {
      kind: 'depends_on',
      step_key: 'ports',
      name: 'Port scan',
      depends_on_before: [],
      depends_on: ['hosts'],
    },
  ],
}

describe('TemplateUpdateCard', () => {
  beforeEach(() => {
    perms = [Permission.ScanWorkflowsRead, Permission.ScanWorkflowsWrite]
    get.mockReset()
    post.mockReset()
  })

  it('shows nothing when no update is offered', async () => {
    get.mockResolvedValue({ available: false, changes: [] })
    const { container } = render(<TemplateUpdateCard workflowId="w1" onApplied={vi.fn()} />)
    await waitFor(() => expect(get).toHaveBeenCalled())
    expect(container).toBeEmptyDOMElement()
  })

  it('previews the changes and applies them with the reviewed digest', async () => {
    get.mockResolvedValue(update)
    post.mockResolvedValue({ id: 'w1' })
    const onApplied = vi.fn()
    render(<TemplateUpdateCard workflowId="w1" onApplied={onApplied} />)
    expect(await screen.findByText('Update available: add Host discovery')).toBeInTheDocument()

    await userEvent.click(screen.getByRole('button', { name: 'Review' }))
    expect(screen.getByText('Add the step Host discovery')).toBeInTheDocument()
    expect(screen.getByText('Port scan now runs after')).toBeInTheDocument()
    // Nothing is applied by looking at it.
    expect(post).not.toHaveBeenCalled()

    await userEvent.click(screen.getByRole('button', { name: 'Apply update' }))
    expect(post).toHaveBeenCalledWith('/api/v1/scan-workflows/w1/template-update/apply', {
      template_digest: 'd1',
    })
    await waitFor(() => expect(onApplied).toHaveBeenCalled())
  })

  it('a reader cannot apply or dismiss', async () => {
    perms = [Permission.ScanWorkflowsRead]
    get.mockResolvedValue(update)
    render(<TemplateUpdateCard workflowId="w1" onApplied={vi.fn()} />)
    await userEvent.click(await screen.findByRole('button', { name: 'Review' }))
    expect(screen.getByText('Apply update').closest('button')).toBeDisabled()
    expect(screen.getByText('Dismiss').closest('button')).toBeDisabled()
  })

  it('waits for an unpublished draft', async () => {
    get.mockResolvedValue(update)
    render(<TemplateUpdateCard workflowId="w1" hasDraft onApplied={vi.fn()} />)
    await userEvent.click(await screen.findByRole('button', { name: 'Review' }))
    expect(screen.getByRole('button', { name: 'Apply update' })).toBeDisabled()
    expect(screen.getByRole('status')).toHaveTextContent('publish or discard it first')
  })
})
