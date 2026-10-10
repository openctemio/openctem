/**
 * Settings › Asset sources (RFC-069): the form starts from the effective
 * policy, saves only the trusted kinds in their order, and refuses a TTL out
 * of range.
 */
import { describe, it, expect, vi } from 'vitest'
import { render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { AssetSourcesSettingsForm } from '../asset-sources-settings'
import type { ReconciliationSettings } from '../../lib/attribute-sources'

vi.mock('sonner', () => ({ toast: { success: vi.fn(), error: vi.fn() } }))

const policy = {
  precedence: {
    criticality: ['manual', 'integration', 'import'],
    owner_ref: ['manual', 'integration', 'import'],
    data_classification: ['manual', 'integration', 'import'],
    exposure: ['manual', 'scan', 'integration', 'import'],
  },
  ttl_days: { integration: 30, import: 90, scan: 30 },
}
const settings: ReconciliationSettings = {
  precedence: {},
  ttl_days: {},
  effective: policy,
  defaults: policy,
}

describe('AssetSourcesSettingsForm', () => {
  it('saves the trusted kinds in their order', async () => {
    const onSave = vi.fn().mockResolvedValue(undefined)
    const user = userEvent.setup()
    render(<AssetSourcesSettingsForm settings={settings} canEdit onSave={onSave} />)

    const crit = screen.getByRole('list', { name: 'Criticality precedence' })
    // Scan is listed last and untrusted for criticality by default.
    expect(within(crit).getByText('not trusted')).toBeInTheDocument()
    const scanBox = document.getElementById('trust-criticality-scan')
    expect(scanBox).not.toBeNull()
    await user.click(scanBox as HTMLElement)
    await user.click(screen.getByRole('button', { name: 'Move Import up for Criticality' }))
    await user.click(screen.getByRole('button', { name: /Save changes/ }))

    expect(onSave).toHaveBeenCalledTimes(1)
    const saved = onSave.mock.calls[0][0]
    expect(saved.precedence.criticality).toEqual(['import', 'integration', 'scan'])
    expect(saved.precedence.exposure).toEqual(['scan', 'integration', 'import'])
    expect(saved.ttl_days).toEqual({ integration: 30, import: 90, scan: 30 })
  })

  it('refuses a TTL out of range', async () => {
    const user = userEvent.setup()
    render(<AssetSourcesSettingsForm settings={settings} canEdit onSave={vi.fn()} />)
    const scan = screen.getByLabelText('Scan', { selector: 'input' })
    await user.clear(scan)
    await user.type(scan, '5000')
    expect(screen.getByText(/whole number of days/)).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /Save changes/ })).toBeDisabled()
  })

  it('is read-only without the right to edit', () => {
    render(<AssetSourcesSettingsForm settings={settings} canEdit={false} onSave={vi.fn()} />)
    expect(screen.queryByRole('button', { name: /Save changes/ })).not.toBeInTheDocument()
  })
})
