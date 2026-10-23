'use client'

import useSWR from 'swr'
import { fetchRegisterPages, type AllPages } from './fetch-all-pages'

/**
 * SWR hook for a register loaded in full (up to REGISTER_ROW_CAP rows). The SWR
 * key is the page-1 URL, so existing `mutate(url)` calls keep working. Pass a
 * null URL to skip the request.
 */
export function useRegisterPages<T>(firstPageUrl: string | null) {
  return useSWR<AllPages<T>>(firstPageUrl, (url: string) => fetchRegisterPages<T>(url), {
    revalidateOnFocus: false,
  })
}
