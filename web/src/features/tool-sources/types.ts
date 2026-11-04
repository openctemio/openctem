/** An organization's key for a third-party source a scan tool queries (API: /api/v1/tool-sources). */
export interface ToolSourceKey {
  set: boolean
  /** The last four characters; the value itself is never returned. */
  last4?: string
  enabled: boolean
  updated_at?: string | null
  updated_by_name?: string | null
  last_used_at?: string | null
}

export interface ToolSource {
  id: string
  name: string
  tools: string[]
  /** "key" is one value; "pair" is two parts joined by ":". */
  format: 'key' | 'pair'
  format_hint?: string
  docs_url?: string
  key?: ToolSourceKey | null
}

export interface ToolSourcesResponse {
  sources: ToolSource[]
}
