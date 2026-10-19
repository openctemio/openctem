import { describe, it, expect, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import { ErrorState } from '../error-state'
import { ApiClientError } from '@/lib/api/error-handler'
import { accessStateOf } from '@/lib/api/access-state'

// research/188 A-009: a missing permission was shown as "module not enabled"
// or as the raw API message with a Retry that cannot help.
describe('ErrorState tells a refusal from a failure', () => {
  it('a permission refusal names the grant, shows no raw message and no Retry', () => {
    const err = new ApiClientError(
      'forbidden: these figures cover the whole organization; they need the dashboards:org:view permission or full data access',
      'FORBIDDEN',
      403,
      { any_of: ['dashboards:org:view'] }
    )
    render(<ErrorState title="program metrics" error={err} onRetry={vi.fn()} />)
    expect(screen.getByText('You do not have access to program metrics')).toBeInTheDocument()
    expect(screen.getByText(/You need one of these permissions/)).toBeInTheDocument()
    expect(screen.queryByText(/^forbidden:/)).toBeNull()
    expect(screen.queryByRole('button', { name: /Retry/ })).toBeNull()
  })

  it('a refusal without details still says who can grant it', () => {
    const err = new ApiClientError('Insufficient permissions', 'FORBIDDEN', 403)
    render(<ErrorState title="program maturity" error={err} />)
    expect(
      screen.getByText('Ask an organization administrator to grant access.')
    ).toBeInTheDocument()
  })

  it('a switched-off module says so, not "no access"', () => {
    const err = new ApiClientError('module not enabled', 'MODULE_NOT_ENABLED', 403)
    render(<ErrorState title="Program maturity" error={err} />)
    expect(
      screen.getByText('Program maturity is not enabled for this organization')
    ).toBeInTheDocument()
  })

  it('a failure keeps the message and Retry', () => {
    const err = new ApiClientError('boom', 'INTERNAL_ERROR', 500)
    render(<ErrorState title="program metrics" error={err} onRetry={vi.fn()} />)
    expect(screen.getByText('Failed to load program metrics')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /Retry/ })).toBeInTheDocument()
  })

  it('classifies errors', () => {
    expect(accessStateOf(undefined)).toBeUndefined()
    expect(accessStateOf({ statusCode: 403, code: 'FORBIDDEN' })).toBe('no_access')
    expect(accessStateOf({ statusCode: 403, code: 'MODULE_NOT_ENABLED' })).toBe('module_off')
    expect(accessStateOf({ statusCode: 500 })).toBe('failed')
  })
})
