import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import { ToolSourcesSection } from '../tool-sources-section'
import type { ToolSource } from '../../types'

const setKey = vi.fn()
const setEnabled = vi.fn()
const removeKey = vi.fn()
const mutate = vi.fn()
const toastError = vi.fn()
let perms: string[] = []
let sources: ToolSource[] = []

vi.mock('sonner', () => ({
  toast: { success: vi.fn(), error: (...a: unknown[]) => toastError(...a) },
}))
vi.mock('@/lib/permissions', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@/lib/permissions')>()),
  usePermissions: () => ({ can: (p: string) => perms.includes(p) }),
}))
vi.mock('../../api/use-tool-sources', () => ({
  useToolSources: () => ({ data: { sources }, isLoading: false, error: undefined, mutate }),
  setToolSourceKey: (...a: unknown[]) => setKey(...a),
  setToolSourceEnabled: (...a: unknown[]) => setEnabled(...a),
  removeToolSourceKey: (...a: unknown[]) => removeKey(...a),
}))

const ALL = ['scans:secret_store:read', 'scans:secret_store:write', 'scans:secret_store:delete']

beforeEach(() => {
  vi.clearAllMocks()
  perms = ALL
  sources = [
    {
      id: 'securitytrails',
      name: 'SecurityTrails',
      tools: ['subfinder'],
      format: 'key',
      docs_url: 'https://example.com/st',
      key: { set: true, last4: 'ab12', enabled: true, updated_by_name: 'Jane' },
    },
    {
      id: 'censys',
      name: 'Censys',
      tools: ['subfinder'],
      format: 'pair',
      format_hint: 'TOKEN:ORG_ID',
      key: null,
    },
  ]
  setKey.mockResolvedValue({})
  setEnabled.mockResolvedValue({})
  removeKey.mockResolvedValue(undefined)
})

describe('Tool source keys', () => {
  it('shows only the last four of a set key and Not set otherwise', () => {
    render(<ToolSourcesSection />)
    expect(screen.getByText('•••• ab12')).toBeInTheDocument()
    expect(screen.getByText('Not set')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Rotate key' })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Set key' })).toBeInTheDocument()
  })

  it('sets a key, sends the value once and never renders it', async () => {
    render(<ToolSourcesSection />)
    await userEvent.click(screen.getByRole('button', { name: 'Rotate key' }))
    const input = screen.getByLabelText('Key')
    expect(input).toHaveAttribute('type', 'password')
    expect(input).toHaveAttribute('autocomplete', 'off')
    await userEvent.type(input, 'secretvalue99')
    await userEvent.click(screen.getByRole('button', { name: 'Save key' }))
    await waitFor(() => expect(setKey).toHaveBeenCalledWith('securitytrails', 'secretvalue99'))
    await waitFor(() => expect(screen.queryByLabelText('Key')).not.toBeInTheDocument())
    expect(document.body.innerHTML).not.toContain('secretvalue99')
    expect(mutate).toHaveBeenCalled()
  })

  it('validates a pair and shows its format hint without calling the API', async () => {
    render(<ToolSourcesSection />)
    await userEvent.click(screen.getByRole('button', { name: 'Set key' }))
    expect(screen.getByText('Format: TOKEN:ORG_ID')).toBeInTheDocument()
    await userEvent.type(screen.getByLabelText('Key'), 'nocolon')
    await userEvent.click(screen.getByRole('button', { name: 'Save key' }))
    expect(screen.getByText(/two parts joined by one colon/)).toBeInTheDocument()
    expect(setKey).not.toHaveBeenCalled()
  })

  it('reports a failed save (for example a step-up refusal) and keeps the dialog', async () => {
    setKey.mockRejectedValueOnce(new Error('Sign in again'))
    render(<ToolSourcesSection />)
    await userEvent.click(screen.getByRole('button', { name: 'Rotate key' }))
    await userEvent.type(screen.getByLabelText('Key'), 'abc')
    await userEvent.click(screen.getByRole('button', { name: 'Save key' }))
    await waitFor(() => expect(toastError).toHaveBeenCalled())
    expect(screen.getByLabelText('Key')).toBeInTheDocument()
  })

  it('toggles enabled; the switch is disabled without a key', async () => {
    render(<ToolSourcesSection />)
    const sw = screen.getByRole('switch', { name: 'Use the key for SecurityTrails' })
    expect(screen.getByRole('switch', { name: 'Use the key for Censys' })).toBeDisabled()
    await userEvent.click(sw)
    await waitFor(() => expect(setEnabled).toHaveBeenCalledWith('securitytrails', false))
  })

  it('removes a key after confirmation', async () => {
    render(<ToolSourcesSection />)
    await userEvent.click(screen.getByRole('button', { name: 'Remove key' }))
    await userEvent.click(screen.getAllByRole('button', { name: 'Remove key' }).at(-1)!)
    await waitFor(() => expect(removeKey).toHaveBeenCalledWith('securitytrails'))
  })

  it('hides write actions without write and remove without delete', () => {
    perms = ['scans:secret_store:read']
    render(<ToolSourcesSection />)
    expect(screen.queryByRole('button', { name: 'Rotate key' })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Set key' })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Remove key' })).not.toBeInTheDocument()
    expect(screen.getByRole('switch', { name: 'Use the key for SecurityTrails' })).toBeDisabled()
  })

  it('keeps Remove hidden with write but no delete', () => {
    perms = ['scans:secret_store:read', 'scans:secret_store:write']
    render(<ToolSourcesSection />)
    expect(screen.getByRole('button', { name: 'Rotate key' })).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Remove key' })).not.toBeInTheDocument()
  })
})
