import type { FindingDetail } from '../types'
import { useFindingEvidenceItems } from '../api/use-finding-evidence-items'
import { useFindingValidationEvidenceApi } from '../api/use-findings-api'
import { useFindingAttachments } from '../api/use-finding-attachments'
import { evidenceSourceCount } from '../lib/evidence-count'

/**
 * The number on the Evidence tab: every source the tab renders (code,
 * stacks, notes, attachments, tool evidence, re-verify and validation
 * results). The requests are the ones the tab makes, so they are shared.
 */
export function useFindingEvidenceCount(finding: FindingDetail | null | undefined): number {
  const { data: tool } = useFindingEvidenceItems(finding?.id ?? null)
  const { data: validation } = useFindingValidationEvidenceApi(finding?.id ?? null)
  const { data: uploads } = useFindingAttachments(finding?.id ?? null, finding?.source)
  if (!finding) return 0
  return evidenceSourceCount(finding, {
    toolEvidence: tool?.data?.length ?? 0,
    validationEvidence: validation?.evidence?.length ?? 0,
    uploadedFiles: uploads?.data?.length ?? 0,
  })
}
