import { describe, expect, it, vi, beforeAll } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import { TenableScanFields } from '../new-scan/tenable-scan-fields'

/**
 * The Tenable.sc scan config in the wizard: only connector integrations are
 * offered, and the policy and repository pickers list what that connector's
 * sensor reported its owner allows.
 */

vi.mock('@/features/integrations/api/use-integrations-api', () => ({
  useIntegrationsApi: () => ({
    data: {
      data: [
        {
          id: 'i1',
          name: 'Tenable.sc prod',
          provider: 'tenable',
          config: { engine: 'tenable_sc', execution_mode: 'sensor', sensor_id: 's1' },
          metadata: {
            tenable_sync: {
              catalog: {
                policies: [{ id: 1000003, name: 'Basic Network Scan' }],
                scan_repositories: [{ id: 5, name: 'Datacenter' }],
              },
            },
          },
        },
        {
          id: 'old',
          name: 'Old Nessus',
          provider: 'tenable',
          config: { engine: 'nessus_pro', execution_mode: 'sensor' },
        },
      ],
    },
    isLoading: false,
  }),
}))

beforeAll(() => {
  // Radix Select needs these in jsdom.
  globalThis.ResizeObserver ??= class {
    observe() {}
    unobserve() {}
    disconnect() {}
  } as unknown as typeof ResizeObserver
  Element.prototype.hasPointerCapture ??= () => false
  Element.prototype.scrollIntoView ??= () => {}
})

describe('TenableScanFields', () => {
  it('offers only Tenable.sc connectors and resets the picks when the connector changes', async () => {
    const onChange = vi.fn()
    render(<TenableScanFields value={undefined} onChange={onChange} />)
    await userEvent.click(screen.getByLabelText('Tenable.sc connector'))
    expect(screen.getByRole('option', { name: 'Tenable.sc prod' })).toBeTruthy()
    expect(screen.queryByRole('option', { name: 'Old Nessus' })).toBeNull()
    await userEvent.click(screen.getByRole('option', { name: 'Tenable.sc prod' }))
    expect(onChange).toHaveBeenCalledWith({ integration_id: 'i1', policy_id: 0, repository_id: 0 })
  })

  it('lists the policies the sensor reported', async () => {
    const onChange = vi.fn()
    render(<TenableScanFields value={{ integration_id: 'i1' }} onChange={onChange} />)
    await userEvent.click(screen.getByLabelText('Scan policy'))
    await userEvent.click(screen.getByRole('option', { name: 'Basic Network Scan (#1000003)' }))
    expect(onChange).toHaveBeenCalledWith({
      integration_id: 'i1',
      policy_id: 1000003,
      repository_id: 0,
    })
  })
})
