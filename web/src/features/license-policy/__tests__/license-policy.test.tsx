import { beforeEach, describe, expect, it, vi } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

const updateLicensePolicy = vi.fn()
vi.mock('../api', async (orig) => ({
  ...(await orig<typeof import('../api')>()),
  updateLicensePolicy: (...a: unknown[]) => updateLicensePolicy(...a),
}))

import { validateRuleMatch } from '../api'
import { firstRuleError, LicensePolicyForm } from '../components/license-policy-form'

// Radix switches and checkboxes measure themselves.
globalThis.ResizeObserver ??= class {
  observe() {}
  unobserve() {}
  disconnect() {}
} as unknown as typeof ResizeObserver

beforeEach(() => updateLicensePolicy.mockReset())

describe('license rule match', () => {
  it('accepts SPDX ids, WITH exceptions and categories', () => {
    for (const ok of [
      'MIT',
      'GPL-2.0-only WITH Classpath-exception-2.0',
      'LicenseRef-acme',
      'category:copyleft',
      'Category:Permissive',
    ]) {
      expect(validateRuleMatch(ok)).toBeNull()
    }
  })
  it('refuses expressions, unknown categories and junk', () => {
    expect(validateRuleMatch('')).toBe('licensePolicy.error.empty')
    expect(validateRuleMatch('category:viral')).toBe('licensePolicy.error.category')
    expect(validateRuleMatch('MIT OR GPL-3.0')).toBe('licensePolicy.error.match')
    expect(validateRuleMatch("MIT'); DROP")).toBe('licensePolicy.error.match')
    expect(
      firstRuleError([
        { match: 'MIT', action: 'allow' },
        { match: 'a b', action: 'deny' },
      ])
    ).toEqual([1, 'licensePolicy.error.match'])
  })
})

describe('license policy form', () => {
  it('adds a scope-limited rule and saves the policy with the section etag', async () => {
    updateLicensePolicy.mockResolvedValue({
      policy: { enabled: true },
      evaluation: {
        links_updated: 3,
        violations: 1,
        findings_created: 1,
        findings_reopened: 0,
        findings_resolved: 0,
      },
    })
    const onSaved = vi.fn()
    render(
      <LicensePolicyForm
        initial={{ enabled: false }}
        etag="W/1"
        formId="lp"
        canEdit
        onSaved={onSaved}
      />
    )
    await userEvent.click(screen.getByRole('switch', { name: 'Evaluate licenses' }))
    await userEvent.click(screen.getByRole('button', { name: 'Add rule' }))
    await userEvent.type(screen.getByLabelText('License or category, rule 1'), 'category:copyleft')
    await userEvent.click(screen.getByLabelText('Test'))
    const form = document.getElementById('lp') as HTMLFormElement
    form.requestSubmit()
    await waitFor(() => expect(updateLicensePolicy).toHaveBeenCalled())
    expect(updateLicensePolicy).toHaveBeenCalledWith(
      {
        enabled: true,
        default: 'allow',
        unknown: 'review',
        review_findings: false,
        rules: [{ match: 'category:copyleft', action: 'deny', scopes: ['test'] }],
      },
      'W/1'
    )
    expect(onSaved).toHaveBeenCalled()
  })

  it('does not save an invalid rule and shows why', async () => {
    render(
      <LicensePolicyForm
        initial={{ enabled: true, rules: [{ match: 'MIT OR GPL', action: 'deny' }] }}
        formId="lp2"
        canEdit
      />
    )
    expect(screen.getByText(/Use one SPDX license id/)).toBeTruthy()
    ;(document.getElementById('lp2') as HTMLFormElement).requestSubmit()
    await new Promise((r) => setTimeout(r, 10))
    expect(updateLicensePolicy).not.toHaveBeenCalled()
  })

  it('is read-only without settings:write', () => {
    render(
      <LicensePolicyForm
        initial={{ enabled: true, rules: [{ match: 'MIT', action: 'allow' }] }}
        formId="lp3"
        canEdit={false}
      />
    )
    expect(screen.queryByRole('button', { name: 'Add rule' })).toBeNull()
    expect(
      (screen.getByLabelText('License or category, rule 1') as HTMLInputElement).disabled
    ).toBe(true)
  })
})
