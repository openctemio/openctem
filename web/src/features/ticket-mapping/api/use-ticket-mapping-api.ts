'use client'

/**
 * Ticket field and status mapping API hooks
 * (api/docs/rfcs/RFC-097-ticket-field-mapping.md). Tenant from the token.
 */

import useSWR, { mutate, type SWRConfiguration } from 'swr'
import { get, post, put, del } from '@/lib/api/client'
import { useTenant } from '@/context/tenant-provider'
import type {
  CatalogView,
  InboundPreview,
  IssueTypeRef,
  MappingProfile,
  MappingSpec,
  MappingVersion,
  ObjectKind,
  OutboundPreview,
  ProfileView,
  ProjectMeta,
  Simulation,
  SpecChange,
  MappingRow,
  ValidationIssue,
} from '../types/ticket-mapping.types'

const BASE = '/api/v1/integrations/ticket-mappings'

const quiet: SWRConfiguration = {
  revalidateOnFocus: false,
  shouldRetryOnError: false,
}

export interface ProfileList {
  data: MappingProfile[]
  total: number
  page: number
  per_page: number
}

export function useMappingCatalog(kind: ObjectKind | undefined) {
  const { currentTenant } = useTenant()
  const key = currentTenant && kind ? `${BASE}/catalog?object_kind=${kind}` : null
  return useSWR<CatalogView>(key, (u: string) => get<CatalogView>(u), {
    ...quiet,
    dedupingInterval: 60_000,
  })
}

export function useMappingProfiles(page = 1, perPage = 50) {
  const { currentTenant } = useTenant()
  const key = currentTenant ? `${BASE}?page=${page}&per_page=${perPage}` : null
  return useSWR<ProfileList>(key, (u: string) => get<ProfileList>(u), quiet)
}

export function useMappingProfile(id: string | undefined) {
  const { currentTenant } = useTenant()
  const key = currentTenant && id ? `${BASE}/${id}` : null
  return useSWR<ProfileView>(key, (u: string) => get<ProfileView>(u), quiet)
}

export function useMappingVersions(id: string | undefined) {
  const { currentTenant } = useTenant()
  const key = currentTenant && id ? `${BASE}/${id}/versions` : null
  return useSWR<{ versions: MappingVersion[] }>(
    key,
    (u: string) => get<{ versions: MappingVersion[] }>(u),
    quiet
  )
}

export function useProjectMeta(
  integrationId: string | undefined,
  projectKey: string | undefined,
  issueTypeId: string | undefined,
  projectId?: string
) {
  const { currentTenant } = useTenant()
  const params = new URLSearchParams()
  if (projectKey) params.set('project_key', projectKey)
  if (issueTypeId) params.set('issue_type_id', issueTypeId)
  if (projectId) params.set('project_id', projectId)
  const key =
    currentTenant && integrationId && projectKey && issueTypeId
      ? `/api/v1/integrations/${integrationId}/jira/metadata?${params.toString()}`
      : null
  return useSWR<ProjectMeta>(key, (u: string) => get<ProjectMeta>(u), {
    ...quiet,
    dedupingInterval: 120_000,
  })
}

export function useIssueTypes(integrationId: string | undefined, projectKey: string | undefined) {
  const { currentTenant } = useTenant()
  const key =
    currentTenant && integrationId && projectKey
      ? `/api/v1/integrations/${integrationId}/jira/issue-types?project_key=${encodeURIComponent(projectKey)}`
      : null
  return useSWR<{ issue_types: IssueTypeRef[] }>(
    key,
    (u: string) => get<{ issue_types: IssueTypeRef[] }>(u),
    quiet
  )
}

export function invalidateMappings(id?: string) {
  return mutate(
    (key) => typeof key === 'string' && (key.startsWith(BASE) || (!!id && key.includes(id))),
    undefined,
    { revalidate: true }
  )
}

export interface CreateMappingInput {
  integration_id: string
  object_kind: ObjectKind
  project_key: string
  project_id?: string
  issue_type_id: string
  issue_type?: string
  name?: string
  preset?: string
}

export const mappingApi = {
  create: (input: CreateMappingInput) =>
    post<{ mapping: ProfileView; issues: ValidationIssue[] }>(BASE, input),
  remove: (id: string) => del<void>(`${BASE}/${id}`),
  saveDraft: (id: string, spec: MappingSpec, expectedDraft: number, note = '') =>
    put<{ version: MappingVersion; issues: ValidationIssue[] }>(`${BASE}/${id}/draft`, {
      spec,
      note,
      expected_draft: expectedDraft,
    }),
  discardDraft: (id: string) => del<void>(`${BASE}/${id}/draft`),
  publish: (id: string, draft: number) =>
    post<{ version: MappingVersion; issues: ValidationIssue[] }>(`${BASE}/${id}/publish`, {
      draft,
    }),
  rollback: (id: string, version: number) =>
    post<{ version: MappingVersion; issues: ValidationIssue[] }>(`${BASE}/${id}/rollback`, {
      version,
    }),
  setDryRun: (id: string, dryRun: boolean) =>
    post<void>(`${BASE}/${id}/dry-run`, { dry_run: dryRun }),
  verify: (id: string, version = 0) =>
    post<{ issues: ValidationIssue[] }>(`${BASE}/${id}/verify?version=${version}`, {}),
  drift: (id: string) =>
    post<{ issues: ValidationIssue[]; drifted: boolean }>(`${BASE}/${id}/drift`, {}),
  diff: (id: string, from: number, to: number) =>
    get<{ changes: SpecChange[] }>(`${BASE}/${id}/diff?from=${from}&to=${to}`),
  exportUrl: (id: string, version: number, format: 'json' | 'yaml') =>
    `${BASE}/${id}/export?version=${version}&format=${format}`,
  exportDoc: (id: string, version: number, format: 'json' | 'yaml') =>
    get<unknown>(`${BASE}/${id}/export?version=${version}&format=${format}`),
  importDoc: (id: string, document: string, expectedDraft: number) =>
    post<{ version: MappingVersion; issues: ValidationIssue[] }>(`${BASE}/${id}/import`, {
      document,
      expected_draft: expectedDraft,
    }),
  copy: (id: string, version: number, target: Omit<CreateMappingInput, 'object_kind'>) =>
    post<{ mapping: ProfileView; issues: ValidationIssue[] }>(`${BASE}/${id}/copy`, {
      version,
      target: { ...target, object_kind: '' },
    }),
  suggest: (id: string) => post<{ rows: MappingRow[] }>(`${BASE}/${id}/suggest`, {}),
  simulate: (
    id: string,
    input: {
      version?: number
      state?: string
      from_status_id?: string
      status_id?: string
      resolution?: string
      current_state?: string
    }
  ) => post<Simulation>(`${BASE}/${id}/simulate`, { version: 0, ...input }),
  preview: (id: string, objectId: string, version = 0) =>
    post<OutboundPreview>(`${BASE}/${id}/preview`, { version, object_id: objectId }),
  inboundPreview: (id: string, issueKey: string, currentState: string, version = 0) =>
    post<InboundPreview>(`${BASE}/${id}/inbound-preview`, {
      version,
      issue_key: issueKey,
      current_state: currentState,
    }),
}
