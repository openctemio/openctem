import { describe, expect, it } from 'vitest'
import { render, screen } from '@testing-library/react'

import { ErrorState } from '../error-state'

const PLAIN =
  'The server did not answer. Nothing was changed. Try again; if it keeps failing, report the problem.'

function apiError(message: string, statusCode: number) {
  return Object.assign(new Error(message), { statusCode })
}

describe('ErrorState message', () => {
  it('replaces a bare code from the server with the plain sentence', () => {
    render(<ErrorState title="threats" error={apiError('internal', 500)} />)
    expect(screen.getByText(PLAIN)).toBeInTheDocument()
    expect(screen.queryByText('internal')).toBeNull()
  })

  it('replaces a server failure even when it is a sentence', () => {
    render(<ErrorState title="threats" error={apiError('database is down right now', 503)} />)
    expect(screen.getByText(PLAIN)).toBeInTheDocument()
  })

  it('keeps a refusal the server explains in a sentence', () => {
    render(<ErrorState title="threats" error={apiError('The filter value is too long.', 400)} />)
    expect(screen.getByText('The filter value is too long.')).toBeInTheDocument()
  })

  it('a record that is not there says so, without Retry or the server text', () => {
    render(
      <ErrorState
        title="this cycle"
        error={apiError('cycle not found not found', 404)}
        onRetry={() => {}}
      />
    )
    expect(screen.getByText("Couldn't find this cycle")).toBeInTheDocument()
    expect(screen.queryByText('cycle not found not found')).toBeNull()
    expect(screen.queryByRole('button', { name: 'Retry' })).toBeNull()
  })
})
