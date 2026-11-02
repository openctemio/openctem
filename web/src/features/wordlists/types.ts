/**
 * Organization wordlists: the wire shapes of /api/v1/wordlists
 * (api docs/architecture/wordlists.md).
 */

export interface Wordlist {
  id: string
  name: string
  description: string
  purpose: 'dns-labels'
  enabled: boolean
  /** Rises when the labels change. */
  version: number
  lines: number
  sha256: string
  /** One label per line; only the single-list read returns it. */
  content?: string
  created_at: string
  updated_at: string
}

export interface WordlistList {
  items: Wordlist[]
  /** The most lists an organization may have. */
  limit: number
}

export interface WordlistReport {
  kept: number
  invalid: number
  secrets: number
  duplicates: number
  examples: string[]
}

export interface WordlistSaveResponse {
  wordlist: Wordlist
  report?: WordlistReport
}

export interface CreateWordlistRequest {
  name: string
  description: string
  text: string
  enabled?: boolean
}

export interface UpdateWordlistRequest {
  name?: string
  description?: string
  text?: string
  enabled?: boolean
}

export interface WordlistPreview {
  root: string
  depth: 'standard' | 'deep'
  pack: { name: string; version: string; digest: string; lines: number } | null
  learned: number
  organization: number
  organization_kept: number
  lists: { id: string; name: string; version: number }[]
  total: number
}
