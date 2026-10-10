/**
 * Bug-bounty programs (RFC-065): list, detail, preview, import, re-import,
 * suspend, reactivate and end. The API decides everything (what an import
 * creates, who may see a program, the terms hash to attest to); the web only
 * shows it. Import, re-import and reactivate ask for step-up, which the
 * shared client handles.
 */

'use client'

import useSWR, { mutate as globalMutate } from 'swr'
import { get, post, put } from '@/lib/api/client'
import { useTenant } from '@/context/tenant-provider'
import { Permission, useHasPermission } from '@/lib/permissions'
import type {
  Program,
  ProgramChange,
  ProgramDetail,
  ProgramInput,
  ProgramPreview,
  ProgramSourceInput,
  ProgramSyncResult,
  PublicProgramPage,
} from './programs-api.types'

const BASE = '/api/v1/programs'

/** The programs the caller may see. */
export function usePrograms() {
  const { currentTenant } = useTenant()
  const can = useHasPermission(Permission.ProgramsRead)
  const key = currentTenant && can ? ['programs', currentTenant.id] : null
  return useSWR<Program[]>(
    key,
    async () => (await get<{ data: Program[] }>(`${BASE}/`))?.data ?? [],
    {
      revalidateOnFocus: false,
    }
  )
}

/** One program with its items, entries and program exclusions. */
export function useProgram(id: string | null) {
  const { currentTenant } = useTenant()
  const can = useHasPermission(Permission.ProgramsRead)
  const key = currentTenant && can && id ? ['program', currentTenant.id, id] : null
  return useSWR<ProgramDetail>(key, () => get<ProgramDetail>(`${BASE}/${id}`), {
    revalidateOnFocus: false,
    shouldRetryOnError: false,
  })
}

/** Refetch every program view after a change. */
export function invalidatePrograms() {
  return globalMutate(
    (key) => Array.isArray(key) && (key[0] === 'programs' || key[0] === 'program'),
    undefined,
    { revalidate: true }
  )
}

export function previewProgram(input: ProgramInput) {
  return post<ProgramPreview>(`${BASE}/preview`, input)
}

export function importProgram(input: ProgramInput) {
  return post<ProgramChange>(`${BASE}/`, input)
}

export function reimportProgram(id: string, input: ProgramInput) {
  return put<ProgramChange>(`${BASE}/${id}/scope`, input)
}

/** The public program catalog, searched by name. */
export function useProgramCatalog(search: string) {
  const { currentTenant } = useTenant()
  const can = useHasPermission(Permission.ProgramsRead)
  const q = new URLSearchParams({ per_page: '50' })
  if (search) q.set('search', search)
  const key = currentTenant && can ? ['program-catalog', currentTenant.id, q.toString()] : null
  return useSWR<PublicProgramPage>(key, () => get<PublicProgramPage>(`${BASE}/catalog?${q}`), {
    revalidateOnFocus: false,
  })
}

/** Confirm targets the feed only suggested for a followed program. */
export function confirmProgramTargets(id: string, targets: string[]) {
  return post<ProgramChange>(`${BASE}/${id}/targets/approve`, { targets })
}

/** Follow a public program: entries stay inactive until someone accepts its terms. */
export function subscribeProgram(publicProgramId: string) {
  return post<ProgramChange>(`${BASE}/subscriptions`, { public_program_id: publicProgramId })
}

/** Accept a program's current terms and confidentiality (unlocks a private program). */
export function attestProgram(id: string, acceptTermsSha256: string) {
  return post<Program>(`${BASE}/${id}/attest`, { accept_terms_sha256: acceptTermsSha256 })
}

export function suspendProgram(id: string) {
  return post<Program>(`${BASE}/${id}/suspend`, {})
}

export function endProgram(id: string) {
  return post<Program>(`${BASE}/${id}/end`, {})
}

export function reactivateProgram(id: string, acceptTermsSha256: string) {
  return post<Program>(`${BASE}/${id}/reactivate`, { accept_terms_sha256: acceptTermsSha256 })
}

/** Where the program's scope comes from (step-up; the token is write-only). */
export function setProgramSource(id: string, input: ProgramSourceInput) {
  return put<Program>(`${BASE}/${id}/source`, input)
}

/** Read the scope from its source now: removals apply, additions wait. */
export function syncProgram(id: string) {
  return post<ProgramSyncResult>(`${BASE}/${id}/sync`, {})
}

/** What accepting the pending terms would do (only when there are some). */
export function useProgramPending(id: string | null, pendingHash: string | undefined) {
  const { currentTenant } = useTenant()
  const can = useHasPermission(Permission.ProgramsRead)
  const key =
    currentTenant && can && id && pendingHash
      ? ['program', currentTenant.id, id, 'pending', pendingHash]
      : null
  return useSWR<ProgramPreview>(key, () => get<ProgramPreview>(`${BASE}/${id}/pending`), {
    revalidateOnFocus: false,
    shouldRetryOnError: false,
  })
}

/** Put the pending terms into effect on the caller's attestation (step-up). */
export function applyPendingTerms(id: string, acceptTermsSha256: string) {
  return post<ProgramChange>(`${BASE}/${id}/pending/apply`, {
    accept_terms_sha256: acceptTermsSha256,
  })
}
