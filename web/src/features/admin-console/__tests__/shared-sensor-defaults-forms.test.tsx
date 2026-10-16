/**
 * Console > System > Platform scanning (RFC-100 §6, §9): "Shared sensors may
 * scan internal zones" reuses the on/off card with its own texts and says
 * which deployment default applies until a value is saved; the anomaly
 * thresholds are changed by a super admin with a reason and a code, and
 * refuse a negative value.
 */
import { describe, expect, it, vi } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

const toast = vi.hoisted(() => ({ success: vi.fn(), error: vi.fn() }))
vi.mock('sonner', () => ({ toast }))

const { PlatformSensorProofForm } = await import('../components/platform-sensor-proof-form')
const { SharedSensorAnomalyForm } = await import('../components/shared-sensor-anomaly-form')

describe('internal zones card', () => {
  it('shows its own texts and the hosted default while nothing is stored', () => {
    render(
      <PlatformSensorProofForm
        prefix="admin.internalZones"
        required={false}
        stored={false}
        defaultValue={false}
        canEdit={false}
        onSave={vi.fn()}
      />
    )
    expect(screen.getByText('Shared sensors may scan internal zones')).toBeInTheDocument()
    expect(screen.getByText(/shared sensors scan public targets only/)).toBeInTheDocument()
    expect(screen.getByText(/default applies \(off\)/)).toBeInTheDocument()
    expect(screen.getByRole('switch')).toBeDisabled()
  })

  it('hides the default hint once a value is stored', () => {
    render(
      <PlatformSensorProofForm
        prefix="admin.internalZones"
        required
        stored
        defaultValue={false}
        canEdit
        onSave={vi.fn()}
      />
    )
    expect(screen.queryByText(/Not saved yet/)).not.toBeInTheDocument()
  })

  it('turns it on with a reason and a code', async () => {
    const onSave = vi.fn().mockResolvedValue(undefined)
    const user = userEvent.setup()
    render(
      <PlatformSensorProofForm
        prefix="admin.internalZones"
        required={false}
        canEdit
        onSave={onSave}
      />
    )
    await user.click(screen.getByRole('switch'))
    await user.click(screen.getByRole('button', { name: 'Save' }))
    expect(await screen.findByText('Let shared sensors scan internal zones?')).toBeInTheDocument()
    await user.type(screen.getByLabelText('Reason'), 'central pool')
    await user.type(screen.getByLabelText('Code from your authenticator'), '123456')
    await user.click(screen.getByRole('button', { name: 'Confirm' }))
    await waitFor(() => expect(onSave).toHaveBeenCalledWith(true, 'central pool', '123456'))
  })
})

describe('SharedSensorAnomalyForm', () => {
  const thresholds = {
    distinct_domains_per_day: 25,
    failures_per_day: 50,
    deny_list_hits_per_day: 5,
  }

  it('is read-only without the super admin role', () => {
    render(<SharedSensorAnomalyForm thresholds={thresholds} canEdit={false} onSave={vi.fn()} />)
    expect(screen.getByLabelText('Distinct domains per day')).toBeDisabled()
    expect(screen.queryByRole('button', { name: 'Save' })).not.toBeInTheDocument()
  })

  it('refuses a negative value and saves a valid change', async () => {
    const onSave = vi.fn().mockResolvedValue(undefined)
    const user = userEvent.setup()
    render(<SharedSensorAnomalyForm thresholds={thresholds} canEdit onSave={onSave} />)
    const domains = screen.getByLabelText('Distinct domains per day')
    await user.clear(domains)
    await user.type(domains, '-3')
    expect(screen.getByRole('button', { name: 'Save' })).toBeDisabled()
    await user.clear(domains)
    await user.type(domains, '10')
    await user.click(screen.getByRole('button', { name: 'Save' }))
    await user.type(screen.getByLabelText('Reason'), 'tighter')
    await user.type(screen.getByLabelText('Code from your authenticator'), '123456')
    await user.click(screen.getByRole('button', { name: 'Confirm' }))
    await waitFor(() =>
      expect(onSave).toHaveBeenCalledWith(
        { ...thresholds, distinct_domains_per_day: 10 },
        'tighter',
        '123456'
      )
    )
  })
})
