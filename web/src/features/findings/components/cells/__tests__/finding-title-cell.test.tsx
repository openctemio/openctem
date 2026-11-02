import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen } from '@testing-library/react'
import { FindingTitleCell, TARGET_MIDDLE, shownTarget } from '../finding-title-cell'
import { findingLocation } from '../../../lib/finding-location'

describe('FindingTitleCell', () => {
  it('makes only the title the open button, its name starting with the title', () => {
    const onOpen = vi.fn()
    render(
      <FindingTitleCell
        title="SQL injection"
        target="api.example.com"
        onOpen={onOpen}
        openLabel="SQL injection, view details"
        meta={<a href="/cve">CVE-2024-1</a>}
      />
    )
    const button = screen.getByRole('button', { name: 'SQL injection, view details' })
    expect(button.textContent).toBe('SQL injection')
    // The meta link is not nested inside the button.
    expect(button.querySelector('a')).toBeNull()
    fireEvent.click(button)
    expect(onOpen).toHaveBeenCalledTimes(1)
  })

  it('renders the title as text without onOpen', () => {
    render(<FindingTitleCell title="Plain" />)
    expect(screen.queryByRole('button')).toBeNull()
  })

  it('keeps the stored title and puts the target on its own line', () => {
    const { container } = render(
      <FindingTitleCell title="CVE-2019-9516 in nginx 1.15.5" target="10.20.30.41:443/tcp" />
    )
    expect(screen.getByText('CVE-2019-9516 in nginx 1.15.5')).toBeTruthy()
    const target = container.querySelector('[data-slot="finding-target"]') as HTMLElement
    expect(target.textContent).toBe('10.20.30.41:443/tcp')
    expect(target.getAttribute('title')).toBe('10.20.30.41:443/tcp')
  })

  it('tells two findings of one issue apart by their targets', () => {
    const a = findingLocation({
      asset: { name: 'edge-01.shop.example.com' },
      network_port: 8443,
      network_transport: 'tcp',
    })
    const b = findingLocation({
      asset: { name: '10.20.30.41' },
      network_port: 443,
      network_transport: 'tcp',
    })
    expect(a.full).toBe('edge-01.shop.example.com:8443/tcp')
    expect(b.full).toBe('10.20.30.41:443/tcp')
    expect(a.full).not.toBe(b.full)
  })

  it('shows no target line when there is no target', () => {
    const { container } = render(<FindingTitleCell title="Weak cipher" target="  " />)
    expect(container.querySelector('[data-slot="finding-target"]')).toBeNull()
  })

  it('cuts a long URL from the middle and keeps the full value on hover', () => {
    const url = `https://portal.example.com/${'a/'.repeat(60)}.git/config`
    const { container } = render(<FindingTitleCell title="Exposed .git directory" target={url} />)
    const target = container.querySelector('[data-slot="finding-target"]') as HTMLElement
    expect(target.textContent!.length).toBeLessThanOrEqual(TARGET_MIDDLE + 1)
    expect(target.textContent!.endsWith('.git/config')).toBe(true)
    expect(target.getAttribute('title')).toBe(url)
  })

  it('renders scanner text as escaped text, never markup', () => {
    const { container } = render(
      <FindingTitleCell title={'<img src=x onerror=alert(1)>'} target={'host\u202Eevil'} />
    )
    expect(container.querySelector('img')).toBeNull()
    expect(shownTarget('host\u202Eevil')).not.toContain('\u202E')
  })

  it('holds no focusable element, so it can sit inside a row button or link', () => {
    const { container } = render(
      <FindingTitleCell title="t" target="h:1" chips={<span>chip</span>} meta={<span>m</span>} />
    )
    expect(container.querySelector('a,button,[tabindex]')).toBeNull()
  })
})

/**
 * Every list of findings renders its rows with FindingTitleCell, so a finding
 * reads the same everywhere: the issue, then the target it was found on.
 */
const LISTS = [
  'app/(dashboard)/findings/page.tsx',
  'features/findings/components/finding-phone-card.tsx',
  'features/findings/components/triage/triage-queue-panel.tsx',
  'features/findings/components/verify-no-cve-list.tsx',
  'features/findings/components/mark-duplicate-dialog.tsx',
  'features/my-work/components/finding-queue.tsx',
  'features/assets/components/asset-findings.tsx',
  'features/remediation-hub/components/task-detail.tsx',
  'features/exceptions/components/suppression-approve-preview.tsx',
]

describe('finding lists use FindingTitleCell', () => {
  const src = join(__dirname, '../../../../..')
  it.each(LISTS)('%s', (file) => {
    const text = readFileSync(join(src, file), 'utf8')
    expect(text).toContain('<FindingTitleCell')
  })

  it('no list draws the asset and place lines by hand', () => {
    for (const file of LISTS) {
      const text = readFileSync(join(src, file), 'utf8')
      expect(text, file).not.toMatch(/location\??\.(asset|detail)\b/)
    }
  })
})
