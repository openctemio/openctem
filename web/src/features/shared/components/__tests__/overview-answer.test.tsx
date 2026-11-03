import { describe, it, expect } from 'vitest'
import { render, screen } from '@testing-library/react'
import { OverviewAnswer, OverviewActList, OVERVIEW_ACT_MAX } from '../overview-answer'

describe('OverviewAnswer', () => {
  it('shows the one big number and the sentence behind it', () => {
    render(
      <OverviewAnswer
        question="P0 fixed within target"
        value="86%"
        sentence="6 of 7 P0 findings were fixed."
      />
    )
    const value = screen.getByText('86%')
    expect(value.className).toContain('text-4xl')
    expect(screen.getByText('6 of 7 P0 findings were fixed.')).toBeTruthy()
    expect(screen.getByRole('heading', { name: 'P0 fixed within target' })).toBeTruthy()
  })

  it('colours the number only for a problem answer', () => {
    const { rerender } = render(<OverviewAnswer question="q" value="40%" tone="danger" />)
    expect(screen.getByText('40%').className).toContain('text-destructive')
    rerender(<OverviewAnswer question="q" value="40%" />)
    expect(screen.getByText('40%').className).not.toContain('text-destructive')
  })

  it('says not measured in muted body text with the reason, no big number', () => {
    const { container } = render(
      <OverviewAnswer
        question="P0 fixed within target"
        value="0%"
        notMeasured={{ label: 'Not measured', reason: 'No P0 findings in the period.' }}
      />
    )
    const label = screen.getByText('Not measured')
    expect(label.className).toContain('text-muted-foreground')
    expect(label.className).not.toContain('text-4xl')
    expect(screen.getByText('No P0 findings in the period.')).toBeTruthy()
    expect(screen.queryByText('0%')).toBeNull()
    expect(container.querySelector('[data-state="not-measured"]')).toBeTruthy()
  })
})

describe('OverviewActList', () => {
  const item = (i: number, status: 'crit' | 'warn' = 'crit') => ({
    key: `k${i}`,
    label: `Row ${i}`,
    detail: `${i} open`,
    href: `/findings?state=open&n=${i}`,
    status,
    statusLabel: status === 'crit' ? 'Off track' : 'Watch',
  })

  it('renders each row as a link to its list with the status word', () => {
    render(
      <OverviewActList title="Where to act" items={[item(1), item(2, 'warn')]} empty="Nothing" />
    )
    const link = screen.getByRole('link', { name: /Row 1/ })
    expect(link.getAttribute('href')).toBe('/findings?state=open&n=1')
    expect(screen.getByText('Off track').className).toContain('text-destructive')
    expect(screen.getByText('Watch').className).toContain('text-warning')
  })

  it('shows at most five rows', () => {
    render(
      <OverviewActList
        title="Where to act"
        items={[1, 2, 3, 4, 5, 6, 7].map((i) => item(i))}
        empty="Nothing"
      />
    )
    expect(screen.getAllByRole('link')).toHaveLength(OVERVIEW_ACT_MAX)
  })

  it('drops a row whose href is unsafe and says so when none is left', () => {
    render(
      <OverviewActList
        title="Where to act"
        items={[{ ...item(1), href: 'javascript:alert(1)' }]}
        empty="Nothing is off track."
      />
    )
    expect(screen.queryByRole('link')).toBeNull()
    expect(screen.getByText('Nothing is off track.')).toBeTruthy()
  })
})
