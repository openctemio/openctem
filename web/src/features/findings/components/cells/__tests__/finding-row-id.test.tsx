import { describe, expect, it, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import { FindingRowId } from '../finding-row-id'
import { FindingTitleCell } from '../finding-title-cell'

vi.mock('@/context/i18n-provider', () => ({
  useTranslation: () => ({
    t: (_k: string, fb?: string, vars?: Record<string, string | number>) => {
      let s = typeof fb === 'string' ? fb : _k
      for (const [n, v] of Object.entries(vars ?? {})) s = s.replace(`{${n}}`, String(v))
      return s
    },
  }),
}))

describe('FindingRowId', () => {
  it('a CVE is a link to its vulnerability page', () => {
    render(<FindingRowId cve="cve-2023-4966" ruleId="citrix-bleed" />)
    const link = screen.getByRole('link', { name: /CVE-2023-4966/ })
    expect(link.textContent).toBe('CVE-2023-4966')
  })

  it('without a CVE the rule id is plain escaped text with the full value as its tooltip', () => {
    const { container } = render(<FindingRowId ruleId={'python.lang.‮exec-used'} />)
    const id = container.querySelector('[data-slot="finding-row-id"]') as HTMLElement
    expect(screen.queryByRole('link')).toBeNull()
    expect(id.textContent).not.toContain('‮')
    expect(id.getAttribute('title')).toBe(id.textContent)
    expect(id.className).toContain('shrink-0')
  })

  it('renders nothing without an id', () => {
    const { container } = render(<FindingRowId cve={null} ruleId=" " />)
    expect(container.firstChild).toBeNull()
  })
})

describe('FindingTitleCell in a table row', () => {
  it('one line: no target line when none is passed, the whole title as the pointer tooltip', () => {
    const { container } = render(
      <FindingTitleCell
        title="OpenSSH signal handler race allows remote code execution"
        onOpen={() => {}}
        openLabel="OpenSSH signal handler race allows remote code execution, view details"
        findingId="f-1"
        chips={<FindingRowId cve="CVE-2024-6387" />}
      />
    )
    expect(container.querySelector('[data-slot="finding-target"]')).toBeNull()
    const link = container.querySelector('[data-slot="finding-title-link"]') as HTMLElement
    expect(link.getAttribute('title')).toBe(
      'OpenSSH signal handler race allows remote code execution'
    )
    expect(link.parentElement?.contains(screen.getByText('CVE-2024-6387'))).toBe(true)
  })
})
