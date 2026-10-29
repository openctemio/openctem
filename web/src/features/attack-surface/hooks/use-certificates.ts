'use client'

import useSWR from 'swr'
import { get } from '@/lib/api/client'
import { Permission, usePermissions } from '@/lib/permissions'
import {
  certificateStatsUrl,
  certificatesUrl,
  type CertificateFilters,
  type CertificateRow,
  type CertificateStats,
} from '../lib/certificates'

interface CertificatePage {
  data?: CertificateRow[]
  total?: number
}

const swrConfig = {
  revalidateOnFocus: false,
  keepPreviousData: true,
  shouldRetryOnError: (error: { statusCode?: number }) =>
    !((error?.statusCode ?? 0) >= 400 && (error?.statusCode ?? 0) < 500),
}

/** One page of the Certificates list; nothing is fetched without assets:read. */
export function useCertificates(f: CertificateFilters, page: { page: number; perPage: number }) {
  const { can } = usePermissions()
  const key = can(Permission.AssetsRead) ? certificatesUrl(f, page) : null
  const { data, error, isLoading, mutate } = useSWR<CertificatePage>(
    key,
    (u: string) => get<CertificatePage>(u),
    swrConfig
  )
  return { rows: data?.data ?? [], total: data?.total ?? 0, error, isLoading, mutate }
}

/** Counts by status for the same filters (the summary strip). */
export function useCertificateStats(f: CertificateFilters) {
  const { can } = usePermissions()
  const key = can(Permission.AssetsRead) ? certificateStatsUrl({ q: f.q }) : null
  return useSWR<CertificateStats>(key, (u: string) => get<CertificateStats>(u), swrConfig)
}

/** Every certificate of a filter, for the export (bounded). */
export async function fetchAllCertificates(f: CertificateFilters): Promise<CertificateRow[]> {
  const PER_PAGE = 100
  const MAX_PAGES = 20
  const out: CertificateRow[] = []
  for (let page = 1; page <= MAX_PAGES; page++) {
    const res = await get<CertificatePage>(certificatesUrl(f, { page, perPage: PER_PAGE }))
    const data = res.data ?? []
    out.push(...data)
    if (data.length < PER_PAGE || out.length >= (res.total ?? 0)) break
  }
  return out
}
