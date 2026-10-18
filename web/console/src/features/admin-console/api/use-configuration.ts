'use client'

import useSWR from 'swr'
import { adminFetcher } from '@console/lib/admin-api/client'
import type { ConfigurationItem } from '../types'

/** The Configuration page: every operator setting and where it comes from. */
export function useConfiguration() {
  return useSWR<{ data: ConfigurationItem[] }>('/configuration', adminFetcher, {
    revalidateOnFocus: false,
  })
}
