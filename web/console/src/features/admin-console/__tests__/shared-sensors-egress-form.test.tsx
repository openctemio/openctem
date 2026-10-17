import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'

import { SharedSensorsEgressForm, parseAddresses } from '../components/shared-sensors-egress-form'

describe('parseAddresses', () => {
  it('splits on lines, commas and spaces and drops blanks', () => {
    expect(parseAddresses(' 203.0.113.1\n\n198.51.100.0/24, 2001:db8::1 ')).toEqual([
      '203.0.113.1',
      '198.51.100.0/24',
      '2001:db8::1',
    ])
  })
})

describe('SharedSensorsEgressForm', () => {
  it('is read-only for an administrator who is not a super admin', () => {
    render(
      <SharedSensorsEgressForm
        global={['203.0.113.1']}
        regions={{ eu: ['198.51.100.7'] }}
        canEdit={false}
        onSave={vi.fn()}
      />
    )
    expect(screen.getByLabelText('All regions')).toBeDisabled()
    expect(screen.getByLabelText('Region')).toHaveValue('eu')
    expect(screen.queryByRole('button', { name: 'Add a region' })).not.toBeInTheDocument()
  })

  it('sends the lists with a reason and a code', async () => {
    const onSave = vi.fn().mockResolvedValue(undefined)
    render(<SharedSensorsEgressForm global={[]} regions={{}} canEdit onSave={onSave} />)
    fireEvent.change(screen.getByLabelText('All regions'), {
      target: { value: '203.0.113.1\n203.0.113.2' },
    })
    fireEvent.click(screen.getByRole('button', { name: 'Add a region' }))
    fireEvent.change(screen.getByLabelText('Region'), { target: { value: 'eu' } })
    fireEvent.change(screen.getByLabelText('Addresses of region eu'), {
      target: { value: '198.51.100.0/24' },
    })
    fireEvent.click(screen.getByRole('button', { name: 'Save' }))
    fireEvent.change(screen.getByLabelText('Reason'), { target: { value: 'new range' } })
    fireEvent.change(screen.getByLabelText(/code/i), { target: { value: '123456' } })
    fireEvent.click(screen.getByRole('button', { name: 'Confirm' }))
    await waitFor(() =>
      expect(onSave).toHaveBeenCalledWith(
        ['203.0.113.1', '203.0.113.2'],
        { eu: ['198.51.100.0/24'] },
        'new range',
        '123456'
      )
    )
  })

  it('refuses a region with addresses but no name, and a region listed twice', () => {
    render(<SharedSensorsEgressForm global={[]} regions={{}} canEdit onSave={vi.fn()} />)
    fireEvent.click(screen.getByRole('button', { name: 'Add a region' }))
    fireEvent.change(screen.getByLabelText('Addresses of region -'), {
      target: { value: '203.0.113.1' },
    })
    expect(screen.getByText('Name every region that has addresses.')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Save' })).toBeDisabled()
  })
})
