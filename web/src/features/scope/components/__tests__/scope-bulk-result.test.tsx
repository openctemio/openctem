import { describe, expect, it, vi } from 'vitest'
import { render, screen, within } from '@testing-library/react'

vi.mock('@/context/i18n-provider', () => ({
  useTranslation: () => ({
    t: (_k: string, fallback: string, vars?: Record<string, string | number>) =>
      Object.entries(vars ?? {}).reduce((s, [k, v]) => s.replace(`{${k}}`, String(v)), fallback),
  }),
}))

const { ScopeBulkResult } = await import('../scope-bulk-result')

describe('ScopeBulkResult', () => {
  it('lists each item with its result, the refusal reason and the counts', () => {
    render(
      <ScopeBulkResult
        created={2}
        existing={1}
        refused={1}
        unsent={['late.io']}
        results={[
          { pattern: '*.a.io', target_type: 'domain', result: 'created', status: 'active' },
          { pattern: '*.b.io', target_type: 'domain', result: 'created', status: 'pending' },
          { pattern: '*.c.io', target_type: 'domain', result: 'exists', status: 'active' },
          {
            pattern: 'bad.io',
            target_type: 'domain',
            result: 'refused',
            code: 'SOME_NEW_CODE',
            message: 'The platform does not allow this target.',
          },
        ]}
      />
    )
    expect(screen.getByTestId('scope-bulk-counts')).toHaveTextContent(
      '2 added, 1 already in scope, 1 refused, 1 not sent'
    )
    const rows = screen.getAllByRole('listitem')
    expect(within(rows[0]).getByText('Added')).toBeInTheDocument()
    expect(within(rows[1]).getByText('Added, waiting for approval')).toBeInTheDocument()
    expect(within(rows[2]).getByText('Already in scope')).toBeInTheDocument()
    expect(within(rows[3]).getByText('Refused')).toBeInTheDocument()
    expect(
      within(rows[3]).getByText('The platform does not allow this target.')
    ).toBeInTheDocument()
    expect(within(rows[4]).getByText('Not sent')).toBeInTheDocument()
    expect(within(rows[4]).getByText('late.io')).toBeInTheDocument()
  })
})
