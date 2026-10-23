import axe from 'axe-core'
import { describe, expect, it, vi } from 'vitest'
import { render, screen, fireEvent } from '@testing-library/react'
import type { Finding } from '@/features/findings'
vi.mock('@/features/findings/components/lifecycle/finding-sub-status', () => ({
  FindingSubStatus: () => null,
}))

import { FindingPhoneCard } from '../finding-phone-card'
import { FindingRowMenu } from '../finding-row-menu'

const finding = {
  id: 'f1',
  title: 'SQL injection in login',
  severity: 'high',
  status: 'new',
  cve: 'CVE-2026-0001',
  scanner: 'semgrep',
  priorityClass: 'P1',
  isInKev: true,
  tags: [],
  assets: [],
} as unknown as Finding

function card(
  over: { selectable?: boolean; selected?: boolean; onSelectedChange?: () => void } = {}
) {
  const onOpen = vi.fn()
  const onAction = vi.fn()
  const onSelectedChange = over.onSelectedChange ?? vi.fn()
  const view = render(
    <ul>
      <li>
        <FindingPhoneCard
          finding={finding}
          selection={{
            selectable: over.selectable ?? true,
            selected: over.selected ?? false,
            onSelectedChange,
          }}
          onOpen={onOpen}
          menu={
            <FindingRowMenu
              title={finding.title}
              onAction={onAction}
              canAssign
              canChangeStatus
              canCreateTicket={false}
              canRemediate={false}
              canDelete={false}
            />
          }
        />
      </li>
    </ul>
  )
  return { ...view, onOpen, onAction, onSelectedChange }
}

describe('FindingPhoneCard', () => {
  it('leads with the priority box and keeps severity and status under the title', () => {
    const { container } = card()
    const open = screen.getByText('SQL injection in login').closest('button') as HTMLElement
    expect((open.firstElementChild as HTMLElement).getAttribute('data-slot')).toBe('priority-badge')
    const under = open.querySelector('[data-slot="severity-badge"]') as HTMLElement
    expect(under).not.toBeNull()
    expect(container.querySelector('[data-slot="status-lozenge"]')).not.toBeNull()
  })

  it('shows at most one exploit chip: KEV wins over EPSS, EPSS only from 10 percent', () => {
    const { container, unmount } = card()
    expect(container.querySelectorAll('[data-slot="kev-badge"]')).toHaveLength(1)
    expect(container.querySelectorAll('[data-slot="epss-chip"]')).toHaveLength(0)
    unmount()
    const noKev = { ...finding, isInKev: false, epssScore: 0.9 } as unknown as Finding
    const r = render(
      <FindingPhoneCard
        finding={noKev}
        selection={{ selectable: false, selected: false, onSelectedChange: vi.fn() }}
        onOpen={vi.fn()}
        menu={null}
      />
    )
    expect(r.container.querySelectorAll('[data-slot="epss-chip"]')).toHaveLength(1)
    expect(r.container.querySelectorAll('[data-slot="kev-badge"]')).toHaveLength(0)
    r.unmount()
    const low = { ...finding, isInKev: false, epssScore: 0.05 } as unknown as Finding
    const r2 = render(
      <FindingPhoneCard
        finding={low}
        selection={{ selectable: false, selected: false, onSelectedChange: vi.fn() }}
        onOpen={vi.fn()}
        menu={null}
      />
    )
    expect(r2.container.querySelectorAll('[data-slot="epss-chip"]')).toHaveLength(0)
  })

  it('carries no 10px or 11px text', () => {
    const { container } = card()
    expect(container.innerHTML).not.toMatch(/text-\[1[01]px\]/)
  })

  it('has a checkbox named after the finding and a row menu', () => {
    card()
    expect(
      screen.getByRole('checkbox', { name: /Select finding SQL injection in login/ })
    ).toBeInTheDocument()
    expect(
      screen.getByRole('button', { name: /Actions for SQL injection in login/ })
    ).toBeInTheDocument()
  })

  it('selecting does not open the finding, and opening does not select', () => {
    const { onOpen, onSelectedChange } = card()
    fireEvent.click(screen.getByRole('checkbox'))
    expect(onSelectedChange).toHaveBeenCalledWith(true)
    expect(onOpen).not.toHaveBeenCalled()
    fireEvent.click(screen.getByText('SQL injection in login'))
    expect(onOpen).toHaveBeenCalledWith(finding)
    expect(onSelectedChange).toHaveBeenCalledTimes(1)
  })

  it('shows no checkbox when the user has no bulk action', () => {
    card({ selectable: false })
    expect(screen.queryByRole('checkbox')).not.toBeInTheDocument()
  })

  it('marks a selected card', () => {
    card({ selected: true })
    expect(screen.getByTestId('finding-phone-card')).toHaveAttribute('data-state', 'selected')
    expect(screen.getByRole('checkbox')).toBeChecked()
  })

  it('has no accessibility violations', async () => {
    const { container } = card({ selected: true })
    const res = await axe.run(container, {
      rules: { 'color-contrast': { enabled: false }, region: { enabled: false } },
    })
    expect(res.violations.map((v) => `${v.id}: ${v.nodes.map((n) => n.target.join(' '))}`)).toEqual(
      []
    )
  })
})
