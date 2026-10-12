'use client'

import useSWR, { type SWRConfiguration } from 'swr'
import { get, patch } from '@/lib/api/client'
import type {
  WebEndpointEventResponse,
  WebEndpointParamResponse,
  WebEndpointResponse,
  WebEndpointStatsResponse,
  WebOriginResponse,
  WebPathCatalogEntry,
  WebPathPatternResponse,
} from '@/lib/api/generated'
import {
  CATALOG_URL,
  endpointParamsUrl,
  endpointStatsUrl,
  endpointUrl,
  endpointsUrl,
  eventsUrl,
  originsUrl,
  patternsUrl,
  type EndpointFilters,
  type EventFilters,
  type PageQuery,
} from '../lib/web-surface-url'

/** A list page in the list query contract envelope. */
export interface WebListPage<T> {
  data?: T[]
  total?: number
  page?: number
  per_page?: number
  total_pages?: number
}

const swrConfig: SWRConfiguration = {
  revalidateOnFocus: false,
  keepPreviousData: true,
  shouldRetryOnError: (error) => !(error?.statusCode >= 400 && error?.statusCode < 500),
}

function useList<T>(url: string | null) {
  const { data, error, isLoading, mutate } = useSWR<WebListPage<T>>(
    url,
    (u: string) => get<WebListPage<T>>(u),
    swrConfig
  )
  return { rows: data?.data ?? [], total: data?.total ?? 0, error, isLoading, mutate }
}

export function useWebOrigins(f: EndpointFilters, page: PageQuery, enabled = true) {
  return useList<WebOriginResponse>(enabled ? originsUrl(f, page) : null)
}

export function useWebEndpoints(f: EndpointFilters, page: PageQuery, enabled = true) {
  return useList<WebEndpointResponse>(enabled ? endpointsUrl(f, page) : null)
}

export function useWebPathPatterns(f: EndpointFilters, page: PageQuery, enabled = true) {
  return useList<WebPathPatternResponse>(enabled ? patternsUrl(f, page) : null)
}

export function useWebEndpointEvents(f: EventFilters, page: PageQuery, enabled = true) {
  return useList<WebEndpointEventResponse>(enabled ? eventsUrl(f, page) : null)
}

export function useWebEndpointStats(f: EndpointFilters, enabled = true) {
  return useSWR<WebEndpointStatsResponse>(
    enabled ? endpointStatsUrl(f) : null,
    (u: string) => get<WebEndpointStatsResponse>(u),
    swrConfig
  )
}

export function useWebEndpoint(id: string | null) {
  return useSWR<WebEndpointResponse>(
    id ? endpointUrl(id) : null,
    (u: string) => get<WebEndpointResponse>(u),
    swrConfig
  )
}

export function useWebEndpointParams(id: string | null) {
  return useSWR<{ data?: WebEndpointParamResponse[] }>(
    id ? endpointParamsUrl(id) : null,
    (u: string) => get<{ data?: WebEndpointParamResponse[] }>(u),
    swrConfig
  )
}

export function useWebPathCatalog(enabled = true) {
  return useSWR<{ version?: string; entries?: WebPathCatalogEntry[] }>(
    enabled ? CATALOG_URL : null,
    (u: string) => get<{ version?: string; entries?: WebPathCatalogEntry[] }>(u),
    { ...swrConfig, revalidateIfStale: false }
  )
}

/** Sets an endpoint's state (active or ignored) and/or its labels. */
export function updateWebEndpoint(
  id: string,
  body: { state?: 'active' | 'ignored'; labels?: string[] }
): Promise<WebEndpointResponse> {
  return patch<WebEndpointResponse>(endpointUrl(id), body)
}
