import type { FindingDetail } from '../types'

/** Counts of the sources that are fetched separately from the finding. */
export interface ExtraEvidenceCounts {
  toolEvidence: number
  validationEvidence: number
  uploadedFiles: number
}

/**
 * How many pieces of evidence the Evidence tab shows. The tab lists all of
 * these, so the badge counts all of them (a finding with only re-verify
 * results still reads "1", not nothing).
 */
export function evidenceSourceCount(f: FindingDetail, extra: ExtraEvidenceCounts): number {
  return (
    (f.contextSnippet || f.snippet ? 1 : 0) +
    (f.stacks?.length || 0) +
    (f.relatedLocations?.length || 0) +
    (f.attachments?.length || 0) +
    (f.evidence?.length || 0) +
    extra.toolEvidence +
    extra.validationEvidence +
    extra.uploadedFiles
  )
}
