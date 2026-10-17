/**
 * Console > System > Platform scanning (RFC-100 §6.1): instance scan zones.
 * A super admin adds a zone (ranges, shared sensors, organizations) with a
 * reason and a code; anyone else only reads.
 */
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

const toast = vi.hoisted(() => ({ success: vi.fn(), error: vi.fn() }))
vi.mock('sonner', () => ({ toast }))

const api = vi.hoisted(() => ({
  createInstanceScanZone: vi.fn(),
  updateInstanceScanZone: vi.fn(),
  deleteInstanceScanZone: vi.fn(),
  setInstanceScanZoneSensors: vi.fn(),
  setInstanceScanZoneOrganizations: vi.fn(),
}))
vi.mock('../api/use-instance-scan-zones', () => api)

const { InstanceScanZonesCard, lines } = await import('../components/instance-scan-zones-card')

const zone = {
  id: 'z1',
  name: 'HQ',
  description: '',
  ranges: ['10.20.0.0/16'],
  sensor_ids: ['s1'],
  organization_ids: ['o1', 'o2'],
}

describe('InstanceScanZonesCard', () => {
  beforeEach(() => vi.clearAllMocks())

  it('lists zones read-only without the super admin role', () => {
    render(<InstanceScanZonesCard zones={[zone]} canEdit={false} onChanged={vi.fn()} />)
    expect(screen.getByText('HQ')).toBeInTheDocument()
    expect(screen.getByText('10.20.0.0/16')).toBeInTheDocument()
    expect(screen.getByText('2 organization(s)')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Add zone' })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Edit' })).not.toBeInTheDocument()
  })

  it('says shared sensors scan public targets only when there is no zone', () => {
    render(<InstanceScanZonesCard zones={[]} canEdit onChanged={vi.fn()} />)
    expect(screen.getByText(/scan public targets only/)).toBeInTheDocument()
  })

  it('adds a zone with its sensors and organizations', async () => {
    api.createInstanceScanZone.mockResolvedValue({
      ...zone,
      id: 'new',
      sensor_ids: [],
      organization_ids: [],
    })
    api.setInstanceScanZoneSensors.mockResolvedValue({})
    api.setInstanceScanZoneOrganizations.mockResolvedValue({})
    const onChanged = vi.fn()
    const user = userEvent.setup()
    render(<InstanceScanZonesCard zones={[]} canEdit onChanged={onChanged} />)
    await user.click(screen.getByRole('button', { name: 'Add zone' }))
    await user.type(screen.getByLabelText('Name'), 'Lab')
    await user.type(screen.getByLabelText('Ranges'), '192.168.10.0/24')
    await user.type(screen.getByLabelText('Shared sensor IDs'), 's9')
    await user.type(screen.getByLabelText('Organization IDs'), 'o7')
    expect(screen.getByRole('button', { name: 'Save' })).toBeDisabled()
    await user.type(screen.getByLabelText('Reason'), 'lab scanners')
    await user.type(screen.getByLabelText('Code from your authenticator'), '123456')
    await user.click(screen.getByRole('button', { name: 'Save' }))
    await waitFor(() => expect(onChanged).toHaveBeenCalled())
    expect(api.createInstanceScanZone).toHaveBeenCalledWith({
      name: 'Lab',
      description: '',
      ranges: ['192.168.10.0/24'],
      reason: 'lab scanners',
      totp_code: '123456',
    })
    expect(api.setInstanceScanZoneSensors).toHaveBeenCalledWith('new', {
      ids: ['s9'],
      reason: 'lab scanners',
      totp_code: '123456',
    })
    expect(api.setInstanceScanZoneOrganizations).toHaveBeenCalledWith('new', {
      ids: ['o7'],
      reason: 'lab scanners',
      totp_code: '123456',
    })
  })

  it('splits lines and drops duplicates', () => {
    expect(lines(' a\n\nb, a \n')).toEqual(['a', 'b'])
  })
})
