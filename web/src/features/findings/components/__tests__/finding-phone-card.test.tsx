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
  ruleId: 'rule-1',
  priorityClass: 'P1',
  isInKev: true,
  slaStatus: 'warning',
  slaDeadline: new Date(Date.now() + 5 * 86_400_000).toISOString(),
  location: { asset: 'shop.example.com', detail: '/login', full: 'shop.example.com /login' },
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
              finding={finding}
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
  it('reads top to bottom: priority and menu, title, asset, id and due, severity and status', () => {
    const { container } = card()
    const root = screen.getByTestId('finding-phone-card')
    const slots = Array.from(root.children).map((c) => c.getAttribute('data-slot'))
    expect(slots).toEqual([
      'finding-card-head',
      'finding-title-cell',
      'finding-card-meta',
      'finding-card-state',
    ])
    const head = container.querySelector('[data-slot="finding-card-head"]') as HTMLElement
    expect(head.querySelector('[data-slot="priority-badge"]')).not.toBeNull()
    // The row menu ends the first line.
    expect(head.lastElementChild).toHaveAttribute('data-slot', 'finding-card-menu')
    expect(head.lastElementChild?.querySelector('button')).not.toBeNull()
    expect(container.querySelector('[data-slot="finding-target"]')).toHaveTextContent(
      'shop.example.com'
    )
    const meta = container.querySelector('[data-slot="finding-card-meta"]') as HTMLElement
    expect(meta.querySelector('[data-slot="finding-row-id"]')).toHaveTextContent('CVE-2026-0001')
    expect(meta.querySelector('[data-slot="sla-due-chip"]')).not.toBeNull()
    const state = container.querySelector('[data-slot="finding-card-state"]') as HTMLElement
    expect(state.querySelector('[data-slot="severity-badge"]')).not.toBeNull()
    expect(state.querySelector('[data-slot="status-lozenge"]')).not.toBeNull()
    expect(state.querySelector('[data-slot="kev-badge"]')).not.toBeNull()
    // No separator characters between the parts.
    expect(root.textContent).not.toContain('\u00b7')
  })

  it('shows the rule id when there is no CVE, and no due text without a deadline', () => {
    const noDue = {
      ...finding,
      cve: undefined,
      ruleId: 'go.lang.security.audit.sqli',
      slaDeadline: undefined,
      slaStatus: 'not_applicable',
    } as unknown as Finding
    const { container } = render(
      <FindingPhoneCard
        finding={noDue}
        selection={{ selectable: false, selected: false, onSelectedChange: vi.fn() }}
        onOpen={vi.fn()}
        menu={null}
      />
    )
    expect(container.querySelector('[data-slot="finding-row-id"]')).toHaveTextContent(
      'go.lang.security.audit.sqli'
    )
    expect(container.querySelector('[data-slot="sla-due-chip"]')).toBeNull()
    expect(container.textContent).not.toMatch(/No SLA/)
  })

  it('has no meta line without an id and a deadline', () => {
    const bare = {
      ...finding,
      cve: undefined,
      ruleId: undefined,
      slaDeadline: undefined,
    } as unknown as Finding
    const { container } = render(
      <FindingPhoneCard
        finding={bare}
        selection={{ selectable: false, selected: false, onSelectedChange: vi.fn() }}
        onOpen={vi.fn()}
        menu={null}
      />
    )
    expect(container.querySelector('[data-slot="finding-card-meta"]')).toBeNull()
  })

  it('cuts the title at two lines and keeps the whole text in its name', () => {
    const long = `${'Outdated TLS configuration allows downgrade '.repeat(6)}end`
    render(
      <FindingPhoneCard
        finding={{ ...finding, title: long } as unknown as Finding}
        selection={{ selectable: false, selected: false, onSelectedChange: vi.fn() }}
        onOpen={vi.fn()}
        menu={null}
      />
    )
    const link = screen.getByRole('link', { name: `${long}, view details` })
    expect(link).toHaveClass('line-clamp-2')
    expect(link).toHaveAttribute('href', '/findings/f1')
  })

  it('a tap anywhere on the card opens the finding, once', () => {
    const { container, onOpen } = card()
    fireEvent.click(container.querySelector('[data-slot="finding-card-state"]') as HTMLElement)
    expect(onOpen).toHaveBeenCalledTimes(1)
    fireEvent.click(screen.getByRole('link', { name: /SQL injection in login, view details/ }))
    expect(onOpen).toHaveBeenCalledTimes(2)
    // The menu is its own target.
    fireEvent.click(screen.getByRole('button', { name: /Actions for SQL injection in login/ }))
    expect(onOpen).toHaveBeenCalledTimes(2)
  })

  it('gives the checkbox a touch target of its own', () => {
    const { container } = card()
    const target = container.querySelector('[data-slot="finding-card-select"]') as HTMLElement
    expect(target.tagName).toBe('LABEL')
    expect(target).toHaveClass('size-touch-target')
    expect(target.querySelector('[role="checkbox"]')).not.toBeNull()
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
