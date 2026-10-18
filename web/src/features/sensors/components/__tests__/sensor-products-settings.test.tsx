import { beforeEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react'

import en from '@/lib/i18n/dictionaries/en/sensors.json'
import vi_ from '@/lib/i18n/dictionaries/vi/sensors.json'
import type { CustomProduct } from '@/lib/api/sensor-custom-products-hooks'

const perms = { write: true }
const api = vi.hoisted(() => ({
  items: [] as unknown[],
  sensors: [] as unknown[],
  save: vi.fn(),
  remove: vi.fn(),
  mutate: vi.fn(),
}))

vi.mock('@/lib/permissions', () => ({
  Permission: { SensorsWrite: 'sensors:write' },
  useHasPermission: () => perms.write,
  Can: ({ children }: { children: React.ReactNode }) => (perms.write ? <>{children}</> : null),
}))
vi.mock('sonner', () => ({ toast: { success: vi.fn(), error: vi.fn() } }))
vi.mock('@/lib/api/sensor-hooks', () => ({
  useAllSensors: () => ({ data: { items: api.sensors } }),
}))
vi.mock('@/lib/api/sensor-custom-products-hooks', () => ({
  useCustomProducts: () => ({
    data: { items: api.items },
    error: undefined,
    isLoading: false,
    mutate: api.mutate,
  }),
  saveCustomProduct: api.save,
  deleteCustomProduct: api.remove,
}))

import { SensorProductsSettings } from '../sensor-products-settings'

const acme: CustomProduct = {
  product: 'acme-sensor',
  latest_version: 'v1.4.0',
  min_version: '',
  updated_at: '2026-10-01T10:00:00Z',
}

describe('SensorProductsSettings', () => {
  beforeEach(() => {
    perms.write = true
    api.items = [acme]
    api.sensors = []
    api.save.mockReset()
    api.remove.mockReset()
    api.mutate.mockReset()
  })

  it('lists the recorded products', () => {
    render(<SensorProductsSettings />)
    const row = screen.getByTestId('custom-product-acme-sensor')
    expect(row).toHaveTextContent('v1.4.0')
    expect(row).toHaveTextContent(en['sensors.customProducts.notSet'])
  })

  it('hides every write action without sensors:write', () => {
    perms.write = false
    api.sensors = [{ product: 'other', product_known: false }]
    render(<SensorProductsSettings />)
    expect(screen.getByText(en['sensors.customProducts.readOnly'])).toBeInTheDocument()
    expect(screen.queryByText(en['sensors.customProducts.add'])).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /acme-sensor/ })).not.toBeInTheDocument()
    expect(screen.queryByTestId('custom-product-suggestions')).not.toBeInTheDocument()
  })

  it('edits a product: the name is fixed and PUT carries both versions', async () => {
    api.save.mockResolvedValue(acme)
    render(<SensorProductsSettings />)
    fireEvent.click(
      screen.getByRole('button', {
        name: en['sensors.customProducts.edit'].replace('{product}', 'acme-sensor'),
      })
    )
    expect(screen.getByLabelText(en['sensors.customProducts.product'])).toBeDisabled()
    fireEvent.change(screen.getByLabelText(en['sensors.customProducts.min']), {
      target: { value: '1.2.0' },
    })
    fireEvent.click(screen.getByRole('button', { name: 'Save' }))
    await waitFor(() =>
      expect(api.save).toHaveBeenCalledWith('acme-sensor', {
        latest_version: 'v1.4.0',
        min_version: '1.2.0',
      })
    )
    await waitFor(() => expect(api.mutate).toHaveBeenCalled())
  })

  it('shows the API error message and hints at a bad version shape', async () => {
    api.save.mockRejectedValue(new Error('product is reserved'))
    render(<SensorProductsSettings />)
    fireEvent.click(screen.getByText(en['sensors.customProducts.add']))
    fireEvent.change(screen.getByLabelText(en['sensors.customProducts.product']), {
      target: { value: 'openctemio-x' },
    })
    fireEvent.change(screen.getByLabelText(en['sensors.customProducts.latest']), {
      target: { value: 'nope' },
    })
    expect(screen.getByText(en['sensors.customProducts.versionHint'])).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'Save' }))
    expect(await screen.findByText('product is reserved')).toBeInTheDocument()
  })

  it('offers unknown reported products not yet recorded, once each', () => {
    api.sensors = [
      { product: 'beta-sensor', product_known: false },
      { sensor_product: 'beta-sensor', product_known: false },
      { product: 'acme-sensor', product_known: false },
      { product: 'openctemio-sensor', product_known: true },
    ]
    render(<SensorProductsSettings />)
    const box = screen.getByTestId('custom-product-suggestions')
    expect(within(box).getAllByRole('button')).toHaveLength(1)
    fireEvent.click(within(box).getByRole('button', { name: 'beta-sensor' }))
    expect(screen.getByLabelText(en['sensors.customProducts.product'])).toHaveValue('beta-sensor')
    expect(screen.getByLabelText(en['sensors.customProducts.product'])).not.toBeDisabled()
  })

  it('deletes after confirming', async () => {
    api.remove.mockResolvedValue(undefined)
    render(<SensorProductsSettings />)
    fireEvent.click(
      screen.getByRole('button', {
        name: en['sensors.customProducts.delete'].replace('{product}', 'acme-sensor'),
      })
    )
    fireEvent.click(
      screen.getByRole('button', { name: en['sensors.customProducts.deleteConfirm'] })
    )
    await waitFor(() => expect(api.remove).toHaveBeenCalledWith('acme-sensor'))
    await waitFor(() => expect(api.mutate).toHaveBeenCalled())
  })

  it('has every key in English and Vietnamese', () => {
    const keys = (d: Record<string, string>) =>
      Object.keys(d).filter((k) => k.startsWith('sensors.customProducts.'))
    expect(keys(vi_ as Record<string, string>).sort()).toEqual(
      keys(en as Record<string, string>).sort()
    )
  })
})
