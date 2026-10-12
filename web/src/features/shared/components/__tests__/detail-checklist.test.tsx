import { describe, it, expect } from 'vitest'
import { render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import { DetailChecklist, orderChecks, type DetailCheck } from '../detail-checklist'
import { DetailChipList, DetailCopyId, DetailDisclosure } from '../detail-sheet'

const CHECKS: DetailCheck[] = [
  { key: 'heartbeat', status: 'ok', label: 'Heartbeat', text: '1m ago' },
  { key: 'version', status: 'info', label: 'Version', text: 'Not reported yet' },
  { key: 'key', status: 'warning', label: 'API key', text: 'Expires in 3 days' },
  { key: 'zone', status: 'critical', label: 'Zone', text: 'Not in a zone' },
]

describe('DetailChecklist', () => {
  it('summarises the passing count and folds the list away', () => {
    render(<DetailChecklist checks={CHECKS} />)
    expect(screen.getByRole('button', { name: /Health checks: 1 of 4 passing/ })).toHaveAttribute(
      'aria-expanded',
      'false'
    )
    expect(screen.queryByRole('list', { name: 'Health' })).not.toBeInTheDocument()
  })

  it('says all pass when none fail', () => {
    render(<DetailChecklist checks={CHECKS.slice(0, 2)} />)
    expect(screen.getByRole('button', { name: /All 2 health checks passing/ })).toBeInTheDocument()
  })

  it('shows the failing checks first when opened', async () => {
    render(<DetailChecklist checks={CHECKS} />)
    await userEvent.click(screen.getByRole('button', { name: /passing/ }))
    const rows = within(screen.getByRole('list', { name: 'Health' })).getAllByRole('listitem')
    expect(rows.map((r) => r.getAttribute('data-check'))).toEqual([
      'zone',
      'key',
      'heartbeat',
      'version',
    ])
  })

  it('renders nothing without checks', () => {
    const { container } = render(<DetailChecklist checks={[]} />)
    expect(container).toBeEmptyDOMElement()
  })

  it('orderChecks keeps the order of equal statuses', () => {
    expect(orderChecks(CHECKS.slice(0, 2)).map((c) => c.key)).toEqual(['heartbeat', 'version'])
  })
})

describe('DetailChipList', () => {
  it('lists chips with their meta and data attributes', () => {
    render(
      <DetailChipList
        label="Tools"
        chips={[
          { key: 'nuclei', label: 'nuclei', meta: <span>3.3.0</span>, data: { tool: 'nuclei' } },
          { key: 'trivy', label: 'trivy', muted: true },
        ]}
      />
    )
    const items = within(screen.getByRole('list', { name: 'Tools' })).getAllByRole('listitem')
    expect(items[0]).toHaveAttribute('data-tool', 'nuclei')
    expect(items[0]).toHaveTextContent('nuclei3.3.0')
    expect(screen.getByText('trivy')).toHaveClass('text-muted-foreground')
  })

  it('says none when empty', () => {
    render(<DetailChipList label="Tools" chips={[]} />)
    expect(screen.getByText('none')).toBeInTheDocument()
  })
})

describe('DetailDisclosure and DetailCopyId', () => {
  it('folds content behind a summary', async () => {
    render(
      <DetailDisclosure summary="More details">
        <p>Commit abc123</p>
      </DetailDisclosure>
    )
    expect(screen.getByText('Commit abc123')).not.toBeVisible()
    await userEvent.click(screen.getByText('More details'))
    expect(screen.getByText('Commit abc123')).toBeVisible()
  })

  it('names the copy button after what it copies', () => {
    render(<DetailCopyId id="0193-abc" label="Sensor ID" />)
    expect(screen.getByRole('button', { name: 'Copy sensor ID' })).toHaveTextContent('0193-abc')
  })
})
