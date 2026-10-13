/**
 * Template updates of a tenant's copy of a system scan workflow: the
 * template's later changes the copy can take, applied or dismissed only by
 * a person (API: /scan-workflows/{id}/template-update).
 */

import { get, post } from '@/lib/api/client'
import type { ScanWorkflow } from '@/lib/api'

export interface TemplateChange {
  kind: 'add_step' | 'depends_on'
  step_key: string
  name: string
  capabilities?: string[]
  tool?: string
  depends_on_before?: string[]
  depends_on: string[]
}

export interface TemplateUpdate {
  available: boolean
  source_template_id?: string
  source_template_name?: string
  template_digest?: string
  changes: TemplateChange[]
}

const url = (id: string) => `/api/v1/scan-workflows/${id}/template-update`

export function fetchTemplateUpdate(id: string): Promise<TemplateUpdate> {
  return get<TemplateUpdate>(url(id))
}

export function applyTemplateUpdate(id: string, digest: string): Promise<ScanWorkflow> {
  return post<ScanWorkflow>(`${url(id)}/apply`, { template_digest: digest })
}

export function dismissTemplateUpdate(id: string, digest: string): Promise<void> {
  return post<void>(`${url(id)}/dismiss`, { template_digest: digest })
}

/** The names of the steps an update adds ("Host discovery"). */
export function addedStepNames(update: TemplateUpdate): string[] {
  return update.changes.filter((c) => c.kind === 'add_step').map((c) => c.name || c.step_key)
}
