/**
 * Custom sensor products (api docs/architecture/sensor-compatibility.md): the
 * organization records the latest and minimum release of sensors it builds
 * itself on sdk-go, so its sensors show "update available" and "unsupported".
 * Reads need sensors:read; saving and removing need sensors:write. First-party
 * products are managed by the platform and refused by the API.
 */

'use client'

import useSWR, { type SWRConfiguration } from 'swr'

import { useTenant } from '@/context/tenant-provider'

import { del, get, put } from './client'

export interface CustomProduct {
  product: string
  /** "" = not set. */
  latest_version: string
  /** "" = not set. */
  min_version: string
  updated_at: string
  updated_by?: string
}

export const customProductsPath = '/api/v1/sensors/custom-products'
export const customProductPath = (product: string) =>
  `${customProductsPath}/${encodeURIComponent(product)}`

const config: SWRConfiguration = { revalidateOnFocus: false, shouldRetryOnError: false }

export function useCustomProducts(enabled = true) {
  const { currentTenant } = useTenant()
  return useSWR<{ items: CustomProduct[] }>(
    currentTenant && enabled ? customProductsPath : null,
    (url: string) => get<{ items: CustomProduct[] }>(url),
    config
  )
}

export function saveCustomProduct(
  product: string,
  body: { latest_version: string; min_version: string }
): Promise<CustomProduct> {
  return put<CustomProduct>(customProductPath(product), body)
}

export function deleteCustomProduct(product: string): Promise<void> {
  return del<void>(customProductPath(product))
}
