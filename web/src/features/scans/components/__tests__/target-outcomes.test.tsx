import { describe, expect, it, vi } from 'vitest'
import { render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import { TargetOutcomes } from '../target-outcomes'
import type { SkipGroup } from '@/features/scans/lib/skip-groups'

const names = (n: number, root = 'old.example.com') =>
  Array.from({ length: n }, (_, i) => `n${i}.${root}`)

describe('TargetOutcomes', () => {
  it('says how many it scans and skips; an expected reason is neutral, never red', async () => {
    const groups: SkipGroup[] = [
      { reason: 'unresolved', tone: 'info', count: 412, targets: names(20) },
    ]
    const { container } = render(<TargetOutcomes willScan={121} groups={groups} />)
    expect(screen.getByTestId('outcome-will-scan')).toHaveTextContent('121')
    expect(screen.getByTestId('outcome-skipped')).toHaveTextContent('412')
    expect(screen.getByTestId('outcome-skipped')).not.toHaveAttribute('data-attention')
    expect(container.querySelector('.text-destructive')).toBeNull()
    const row = screen.getByText('Do not resolve in DNS').closest('li')!
    expect(within(row).getByText('Expected')).toBeInTheDocument()

    // Collapsed by default; the list, its fix and a search open on demand.
    expect(within(row).queryByTestId('skip-names')).not.toBeInTheDocument()
    await userEvent.click(within(row).getByRole('button', { expanded: false }))
    expect(within(row).getByRole('button', { expanded: true })).toBeInTheDocument()
    expect(within(row).getByText(/Asset coverage keeps checking their DNS/)).toBeInTheDocument()
    expect(within(row).getAllByRole('listitem')).toHaveLength(20)
    expect(within(row).getByText('and 392 more not listed')).toBeInTheDocument()
    await userEvent.type(within(row).getByLabelText('Search the skipped names'), 'n1')
    // n1, n10..n19
    expect(within(within(row).getByTestId('skip-names')).getAllByRole('listitem')).toHaveLength(11)
    await userEvent.type(within(row).getByLabelText('Search the skipped names'), 'zzz')
    expect(within(row).getByText('No name matches.')).toBeInTheDocument()
  })

  it('flags a reason that needs a fix in amber', () => {
    render(
      <TargetOutcomes
        willScan={0}
        groups={[{ reason: 'zone_no_sensor', tone: 'warning', count: 3, targets: ['10.3.0.1'] }]}
      />
    )
    expect(screen.getByTestId('outcome-skipped')).toHaveAttribute('data-attention', 'true')
    expect(screen.getByText('Needs a fix')).toBeInTheDocument()
  })

  it('offers to remove only the typed targets of a group', async () => {
    const onRemove = vi.fn()
    render(
      <TargetOutcomes
        willScan={1}
        groups={[
          {
            reason: 'unresolved',
            tone: 'info',
            count: 3,
            targets: ['typo.example.com', 'a.example.com', 'b.example.com'],
          },
        ]}
        removable={(t) => t === 'typo.example.com'}
        onRemove={onRemove}
      />
    )
    await userEvent.click(screen.getByRole('button', { expanded: false }))
    await userEvent.click(
      screen.getByRole('button', { name: 'Remove 1 typed target from this scan' })
    )
    expect(onRemove).toHaveBeenCalledWith(['typo.example.com'])
  })

  it('lists a count-only reason without names, and an unknown reason as other', async () => {
    render(
      <TargetOutcomes
        willScan={5}
        variant="run"
        groups={[
          { reason: 'archived', tone: 'info', count: 4, targets: [] },
          { reason: 'brand_new_reason', tone: 'warning', count: 1, targets: ['x'] },
        ]}
      />
    )
    expect(screen.getByText('Scanned')).toBeInTheDocument()
    expect(screen.getByText('Other reasons')).toBeInTheDocument()
    await userEvent.click(screen.getByText('Archived assets'))
    expect(screen.getByText(/Counted only/)).toBeInTheDocument()
  })

  it('says when nothing is skipped', () => {
    render(<TargetOutcomes willScan={3} groups={[]} />)
    expect(screen.getByText('Every target will be scanned.')).toBeInTheDocument()
  })
})
