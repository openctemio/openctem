import { describe, expect, it, vi } from 'vitest'
import { render } from '@testing-library/react'
import type { Finding } from '@/features/findings'
import { TooltipProvider } from '@/components/ui/tooltip'

vi.mock('@/features/findings/components/lifecycle/finding-sub-status', () => ({
  FindingSubStatus: () => null,
}))

import { FindingPhoneCard } from '../finding-phone-card'
import { FindingRowMenu } from '../finding-row-menu'
import { groupDisplayLabel } from '../finding-groups-table'
import { FindingTitleCell } from '../cells/finding-title-cell'
import { FindingAssetCell } from '../cells/finding-asset-cell'
import { FindingRowId } from '../cells/finding-row-id'

/**
 * A list row and a phone card never show a secret or an e-mail address in
 * clear: not in text, not in a `title` tooltip, not in an accessible name.
 * The values are raw here (as if the page had not masked them), so each
 * component is checked on its own.
 */
const EMAIL = 'admin@example.com'
const KEY = 'AKIAIOSFODNN7EXAMPLE'
const TITLE = `Leaked key ${KEY} of ${EMAIL} in the build log`
const PLACE = `https://deploy:hunter2secret@git.example.com/app/config.yml?owner=${EMAIL}`

const finding = {
  id: 'f1',
  title: TITLE,
  severity: 'high',
  status: 'new',
  cve: KEY,
  ruleId: `secrets.${KEY}`,
  scanner: 'gitleaks',
  priorityClass: 'P1',
  tags: [],
  assets: [{ id: 'a1', name: EMAIL }],
  location: { asset: `repo of ${EMAIL}`, detail: PLACE, full: `repo of ${EMAIL}, ${PLACE}` },
} as unknown as Finding

function expectNothingInClear(container: HTMLElement) {
  const html = container.innerHTML
  for (const secret of [EMAIL, KEY, 'hunter2secret', 'admin@']) {
    expect(html).not.toContain(secret)
  }
  // Checked attribute by attribute too, so a failure names the place.
  for (const el of Array.from(container.querySelectorAll('*'))) {
    for (const attr of ['title', 'aria-label', 'aria-description', 'data-label']) {
      const value = el.getAttribute(attr) ?? ''
      expect(value, `${attr} of <${el.tagName.toLowerCase()}>`).not.toContain(EMAIL)
      expect(value, `${attr} of <${el.tagName.toLowerCase()}>`).not.toContain(KEY)
    }
  }
  expect(container.textContent).not.toContain(EMAIL)
  expect(container.textContent).not.toContain(KEY)
}

describe('masked finding rows', () => {
  it('a phone card with its checkbox and menu shows the masked title and place only', () => {
    const { container } = render(
      <TooltipProvider>
        <FindingPhoneCard
          finding={finding}
          selection={{ selectable: true, selected: false, onSelectedChange: vi.fn() }}
          onOpen={vi.fn()}
          menu={
            <FindingRowMenu
              title={finding.title}
              finding={finding}
              onAction={vi.fn()}
              canAssign
              canChangeStatus
              canCreateTicket
              canRemediate
              canDelete
            />
          }
        />
      </TooltipProvider>
    )
    expectNothingInClear(container)
    // The rest of the title stays, with the previews in place of the values.
    expect(container.textContent).toContain('Leaked key AKIA••••••••MPLE of ***@example.com')
    expect(container.querySelector('[role="checkbox"]')?.getAttribute('aria-label')).toContain(
      'AKIA••••••••MPLE'
    )
    expect(
      container.querySelector('[data-slot="finding-target"]')?.getAttribute('title')
    ).toContain('https://••••••••@git.example.com/app/config.yml?owner=***@example.com')
  })

  it('a table row: the title link, its tooltip and name, the id and the Location cell', () => {
    const { container } = render(
      <TooltipProvider>
        <FindingTitleCell
          title={finding.title}
          target={finding.location?.full}
          onOpen={vi.fn()}
          findingId={finding.id}
          openLabel={`${finding.title}, view details`}
          chips={<FindingRowId cve={finding.cve} ruleId={finding.ruleId} />}
        />
        <FindingAssetCell finding={finding} />
        <FindingAssetCell
          finding={{ ...finding, location: { asset: '', detail: PLACE, full: PLACE } } as Finding}
        />
        <FindingRowMenu
          title={finding.title}
          finding={finding}
          onAction={vi.fn()}
          canAssign={false}
          canChangeStatus={false}
          canCreateTicket={false}
          canRemediate={false}
          canDelete={false}
        />
      </TooltipProvider>
    )
    expectNothingInClear(container)
    const link = container.querySelector('[data-slot="finding-title-link"]') as HTMLElement
    expect(link.getAttribute('href')).toBe('/findings/f1')
    expect(link.getAttribute('title')).toContain('AKIA••••••••MPLE of ***@example.com')
    expect(link.getAttribute('aria-label')).toContain('AKIA••••••••MPLE')
    expect(link.getAttribute('aria-label')).toContain(', view details')
    expect(container.querySelector('[data-slot="finding-row-id"]')?.textContent).toBe(
      'secrets.AKIA••••••••MPLE'
    )
    const names = Array.from(container.querySelectorAll('[data-slot="truncated-text"]')).map(
      (el) => el.getAttribute('aria-label') ?? ''
    )
    expect(names[0]).toContain('repo of ***@example.com')
    expect(names[0]).toContain('https://••••••••@git.example.com')
  })

  it('rows and cards offer no "Show" control', () => {
    const { container } = render(
      <TooltipProvider>
        <FindingPhoneCard
          finding={finding}
          selection={{ selectable: false, selected: false, onSelectedChange: vi.fn() }}
          onOpen={vi.fn()}
          menu={null}
        />
        <FindingAssetCell finding={finding} />
      </TooltipProvider>
    )
    const controls = Array.from(container.querySelectorAll('button, a, [role="button"]'))
    for (const el of controls) {
      const name = `${el.getAttribute('aria-label') ?? ''} ${el.textContent ?? ''}`
      expect(name).not.toMatch(/\b(show|reveal)\b/i)
    }
  })

  it('a group header masks scanner text and keeps an owner name', () => {
    expect(groupDisplayLabel({ group_type: 'rule', label: `Key ${KEY} of ${EMAIL}` })).toBe(
      'Key AKIA••••••••MPLE of ***@example.com'
    )
    expect(groupDisplayLabel({ group_type: 'asset', label: PLACE })).not.toContain('hunter2secret')
    expect(groupDisplayLabel({ group_type: 'cve', label: 'CVE-2024-12345' })).toBe('CVE-2024-12345')
    expect(groupDisplayLabel({ group_type: 'owner', label: 'jane@example.com' })).toBe(
      'jane@example.com'
    )
  })
})
