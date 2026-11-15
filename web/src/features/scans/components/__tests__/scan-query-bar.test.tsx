import { describe, expect, it, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { ListSearch } from '@/features/shared/components/list-search'

vi.mock('@/features/query/api/query-api', () => ({
  queryApi: { parse: vi.fn().mockResolvedValue({ valid: true, text: 'status=active' }) },
}))
vi.mock('@/features/query/components/query-input', () => ({
  QueryInput: (p: { entity: string; ariaLabel?: string; disabled?: boolean }) => (
    <input data-testid="query-input" data-entity={p.entity} aria-label={p.ariaLabel} />
  ),
}))

import { ScanQueryChip, useScanQueryMode } from '../scan-query-bar'

function Field({ search }: { search: URLSearchParams }) {
  const mode = useScanQueryMode(search, vi.fn())
  return <ListSearch value="" onChange={() => undefined} placeholder="Search" query={mode.query} />
}

describe('the scans Query mode', () => {
  it('shows the filter chips cannot show as one Advanced chip; removing it clears fq', async () => {
    const user = userEvent.setup()
    const onChange = vi.fn()
    render(
      <ScanQueryChip
        search={new URLSearchParams('fq=total_runs%3E%3D3&page=2&sort=name')}
        onOpen={vi.fn()}
        onSearchChange={onChange}
      />
    )
    expect(screen.getByTestId('filter-chip-advanced')).toHaveTextContent('total_runs>=3')
    await user.click(screen.getByRole('button', { name: 'Remove the advanced filter' }))
    expect(onChange).toHaveBeenCalledTimes(1)
    expect((onChange.mock.calls[0][0] as URLSearchParams).toString()).toBe('sort=name')
  })

  it('draws nothing without an fq filter', () => {
    const { container } = render(
      <ScanQueryChip
        search={new URLSearchParams('status=active')}
        onOpen={vi.fn()}
        onSearchChange={vi.fn()}
      />
    )
    expect(container).toBeEmptyDOMElement()
  })

  it('the field switches to the shared query box on the scans entity', async () => {
    const user = userEvent.setup()
    render(<Field search={new URLSearchParams('status=active')} />)
    expect(screen.queryByTestId('scans-query-editor')).toBeNull()
    await user.click(screen.getByRole('button', { name: 'Query' }))
    const box = await screen.findByTestId('query-input')
    expect(box).toHaveAttribute('data-entity', 'scans')
    expect(box).toHaveAttribute('aria-label', 'Filter scans as query text')
  })
})
