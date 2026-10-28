'use client'

/**
 * The organization's AI masking policy and its preview (API docs:
 * architecture/ai-context-masking.md). Owners and administrators; a change
 * needs a recent sign-in (the shared API client asks) and is audited.
 *
 * Wire types are written here while the API change lands separately. The
 * read answers null when the route is not there yet (404) or the caller may
 * not read it (403): the section then renders nothing.
 *
 * Secrets are always masked and restricted data is always masked in full;
 * neither is configurable, so the API does not list them.
 */
import useSWR from 'swr'

import { get, post, put } from '@/lib/api/client'
import { ApiClientError } from '@/lib/api/error-handler'

/** The classes an administrator may leave readable in internal data. */
export type AIMaskingClass =
  'hosts' | 'ips' | 'emails' | 'users' | 'url_params' | 'orgs' | 'tickets'

export interface AIMaskingClassState {
  class: AIMaskingClass | string
  masked: boolean
}

export interface AIMaskingPolicy {
  classes: AIMaskingClassState[]
  mask_subdomain_labels: boolean
  terms: string[]
  max_terms: number
  updated_at?: string
  updated_by?: string
}

/** Replaces the policy: `off` lists the classes left readable. */
export interface AIMaskingUpdate {
  off: string[]
  mask_subdomain_labels: boolean
  terms: string[]
}

export type AIPreviewDataClass = 'public' | 'internal' | 'restricted'

export interface AIMaskingPlaceholder {
  token: string
  class: string
}

/** Exactly what the model would get; placeholders carry their class, never their value. */
export interface AIMaskingPreview {
  text: string
  placeholders: AIMaskingPlaceholder[]
  fields_sent: string[]
  fields_withheld: string[]
  data_class: string
}

export const AI_MASKING_URL = '/api/v1/organization/settings/ai/masking'
export const AI_ERR_POLICY_RESTRICTED = 'AI_POLICY_RESTRICTED'
export const AI_ERR_NOTHING_TO_SEND = 'AI_NOTHING_TO_SEND'

/** Term length bounds the API enforces. */
export const AI_TERM_MIN = 3
export const AI_TERM_MAX = 128

export function useAIMasking(enabled: boolean) {
  return useSWR<AIMaskingPolicy | null>(
    enabled ? AI_MASKING_URL : null,
    async (url: string) => {
      try {
        return await get<AIMaskingPolicy>(url)
      } catch (err) {
        if (err instanceof ApiClientError && (err.statusCode === 404 || err.statusCode === 403)) {
          return null
        }
        throw err
      }
    },
    { revalidateOnFocus: false, shouldRetryOnError: false }
  )
}

export async function updateAIMasking(body: AIMaskingUpdate): Promise<AIMaskingPolicy> {
  return put<AIMaskingPolicy>(AI_MASKING_URL, body)
}

export async function previewAIMasking(
  findingId: string,
  dataClass: AIPreviewDataClass
): Promise<AIMaskingPreview> {
  return post<AIMaskingPreview>(`${AI_MASKING_URL}/preview`, {
    finding_id: findingId,
    data_class: dataClass,
  })
}
