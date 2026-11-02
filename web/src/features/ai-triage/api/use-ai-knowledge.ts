'use client'

/**
 * Knowledge sources for AI agents (API docs: architecture/ai-knowledge.md):
 * runbooks, conventions and architecture notes an AI agent may cite. Nothing
 * reaches an AI agent until another person approves it. Approving and
 * deleting a source need a recent sign-in: the shared API client asks for it
 * and retries.
 */
import useSWR from 'swr'

import { del, get, patch, post } from '@/lib/api/client'

export type KnowledgeVisibility = 'organization' | 'teams'
export type KnowledgeDataClass = 'internal' | 'restricted'
export type KnowledgeSourceStatus = 'pending' | 'approved' | 'rejected' | 'disabled'
export type KnowledgeDocumentStatus = 'pending' | 'approved' | 'rejected' | 'superseded'

export interface KnowledgeSource {
  id: string
  name: string
  description: string
  origin: string
  visibility: KnowledgeVisibility
  data_class: KnowledgeDataClass
  status: KnowledgeSourceStatus
  team_ids: string[]
  created_by?: string
  decided_by?: string
  decided_at?: string
  self_approved: boolean
  rejected_reason?: string
  documents: number
  pending_documents: number
  bytes: number
  created_at: string
  updated_at: string
}

export interface KnowledgeDocument {
  id: string
  lineage_id: string
  version: number
  title: string
  status: KnowledgeDocumentStatus
  quarantined: boolean
  quarantine_reason?: string
  content_sha256: string
  bytes: number
  chunks: number
  created_by?: string
  decided_at?: string
  created_at: string
}

export interface KnowledgeSourceDetail extends KnowledgeSource {
  document_versions: KnowledgeDocument[]
}

export interface KnowledgeHit {
  document_id: string
  source_id: string
  source_name: string
  document_title: string
  section: string
  excerpt: string
  score: number
  updated_at: string
}

export interface CreateKnowledgeSource {
  name: string
  description: string
  visibility: KnowledgeVisibility
  data_class: KnowledgeDataClass
  team_ids: string[]
}

export interface AddKnowledgeDocument {
  title: string
  text: string
  /** Any version of an existing document of the source: the new text becomes its next version. */
  replaces?: string
}

/** The API's cap on one document version. */
export const KNOWLEDGE_MAX_DOCUMENT_BYTES = 256 * 1024

/** Error code of an approval that needs the quarantined text acknowledged. */
export const KNOWLEDGE_QUARANTINE_CODE = 'AI_KNOWLEDGE_QUARANTINE'

export const AI_KNOWLEDGE_URL = '/api/v1/ai/knowledge'

const sourceUrl = (id: string, tail = '') =>
  `${AI_KNOWLEDGE_URL}/sources/${encodeURIComponent(id)}${tail}`

const SWR_OPTIONS = { revalidateOnFocus: false, shouldRetryOnError: false } as const

export function useAIKnowledgeSources(enabled = true) {
  return useSWR<KnowledgeSource[]>(
    enabled ? `${AI_KNOWLEDGE_URL}/sources` : null,
    async (url: string) => (await get<{ data: KnowledgeSource[] }>(url)).data ?? [],
    SWR_OPTIONS
  )
}

export function useAIKnowledgeSource(id: string | null) {
  return useSWR<KnowledgeSourceDetail>(
    id ? sourceUrl(id) : null,
    (url: string) => get<KnowledgeSourceDetail>(url),
    SWR_OPTIONS
  )
}

export const createKnowledgeSource = (body: CreateKnowledgeSource) =>
  post<KnowledgeSourceDetail>(`${AI_KNOWLEDGE_URL}/sources`, body)

export const updateKnowledgeSource = (id: string, body: { name: string; description: string }) =>
  patch<KnowledgeSourceDetail>(sourceUrl(id), body)

export const deleteKnowledgeSource = (id: string) => del(sourceUrl(id))

export const approveKnowledgeSource = (id: string, acknowledgeQuarantine: boolean) =>
  post<KnowledgeSourceDetail>(sourceUrl(id, '/approve'), {
    acknowledge_quarantine: acknowledgeQuarantine,
  })

export const rejectKnowledgeSource = (id: string, reason: string) =>
  post<KnowledgeSourceDetail>(sourceUrl(id, '/reject'), { reason })

export const disableKnowledgeSource = (id: string) =>
  post<KnowledgeSourceDetail>(sourceUrl(id, '/disable'), {})

export const addKnowledgeDocument = (id: string, body: AddKnowledgeDocument) =>
  post<KnowledgeDocument>(sourceUrl(id, '/documents'), body)

export const deleteKnowledgeDocument = (id: string) =>
  del(`${AI_KNOWLEDGE_URL}/documents/${encodeURIComponent(id)}`)

export const previewKnowledge = async (aiAgentId: string, query: string) =>
  (
    await post<{ data: KnowledgeHit[] }>(`${AI_KNOWLEDGE_URL}/preview`, {
      ai_agent_id: aiAgentId,
      query,
    })
  ).data ?? []
