'use client'

/**
 * The organization's tool source keys. Writes go through the shared API
 * client, which opens the step-up dialog and retries when the API asks for a
 * recent sign-in. A key value is write-only: the API returns only last4.
 */
import useSWR from 'swr'

import { del, get, patch, put } from '@/lib/api/client'
import type { ToolSource, ToolSourcesResponse } from '../types'

export const TOOL_SOURCES_URL = '/api/v1/tool-sources'

export function useToolSources() {
  return useSWR<ToolSourcesResponse>(TOOL_SOURCES_URL, (url: string) =>
    get<ToolSourcesResponse>(url)
  )
}

export function setToolSourceKey(id: string, value: string): Promise<ToolSource> {
  return put<ToolSource>(`${TOOL_SOURCES_URL}/${encodeURIComponent(id)}/key`, { value })
}

export function setToolSourceEnabled(id: string, enabled: boolean): Promise<ToolSource> {
  return patch<ToolSource>(`${TOOL_SOURCES_URL}/${encodeURIComponent(id)}`, { enabled })
}

export function removeToolSourceKey(id: string): Promise<void> {
  return del<void>(`${TOOL_SOURCES_URL}/${encodeURIComponent(id)}/key`)
}
