'use client'

import useSWR from 'swr'
import { get } from '@/lib/api/client'
import type { WebEndpointResponse } from '@/lib/api/generated'
import { webPathsUrl, type PathFilters, type PathLevelOptions } from '../lib/web-paths-url'

/*
 * GET /api/v1/assets/{id}/web-paths. The shapes below follow the server's
 * WebPathsResponse (server/internal/infra/http/handler/web_endpoint_paths_handler.go);
 * they move to the generated contract once the route reaches this branch.
 */

export interface WebPathFolder {
  name: string
  path: string
  param: boolean
  endpoints: number
  out_of_scope: number
  findings: number
  top_severity?: string
  has_folders: boolean
}

export interface WebPathTotals {
  recorded: number
  endpoints: number
  hidden: number
  out_of_scope: number
  findings: number
  unrecorded_findings: number
  top_severity?: string
  origin_findings: number
  capped: boolean
}

export type WebPathEndpoint = WebEndpointResponse & {
  finding_count: number
  top_severity?: string
}

export interface WebNodeFinding {
  id: string
  title: string
  severity: string
  status: string
  path: string
}

export interface WebPathLevel {
  path: string
  totals: WebPathTotals
  folders: WebPathFolder[]
  folders_truncated: boolean
  endpoints: WebPathEndpoint[]
  endpoint_total: number
  page: number
  per_page: number
  node_findings?: WebNodeFinding[]
  node_finding_total?: number
}

/**
 * One level of an origin's path tree. Keeps the previous answer while the
 * next loads, so the tree and the table never collapse between levels.
 */
export function useWebPaths(
  assetId: string | null,
  path: string,
  filters: PathFilters,
  options: PathLevelOptions = {}
) {
  const url = assetId ? webPathsUrl(assetId, path, filters, options) : null
  return useSWR<WebPathLevel>(url, (u: string) => get<WebPathLevel>(u), {
    revalidateOnFocus: false,
    keepPreviousData: true,
    shouldRetryOnError: (error) => !(error?.statusCode >= 400 && error?.statusCode < 500),
  })
}
