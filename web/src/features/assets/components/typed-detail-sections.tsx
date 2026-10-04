import { DetailField, DetailFieldGrid, DetailSection } from '@/features/shared'
import type { Asset } from '../types'
import type { DetailSectionConfig } from '../types/page-config.types'
import { resolveDetailSections } from '../lib/detail-sections'
import { NotCollectedNote } from './service-cells'

/**
 * A typed page's drawer sections. Fields with no value are left out, and
 * the facts no scan collected are named once, in a muted "Not collected
 * yet: …" line at the end of the last section (ui-style-contract §7,
 * "Unknown facts"), instead of an "Unknown" in each row.
 */
export function TypedDetailSections({
  sections,
  asset,
}: {
  sections: readonly DetailSectionConfig[]
  asset: Asset
}) {
  const resolved = resolveDetailSections(sections, asset)
  const note = <NotCollectedNote items={resolved.notCollected} />
  if (resolved.sections.length === 0)
    return resolved.notCollected.length > 0 && sections[0] ? (
      <DetailSection title={sections[0].title}>{note}</DetailSection>
    ) : null
  const last = resolved.sections.length - 1
  return (
    <>
      {resolved.sections.map((section, si) => (
        <DetailSection key={si} title={section.title}>
          <DetailFieldGrid>
            {section.fields.map((field, fi) => (
              <DetailField key={fi} label={field.label} full={field.fullWidth}>
                {field.value}
              </DetailField>
            ))}
          </DetailFieldGrid>
          {si === last && note}
        </DetailSection>
      ))}
    </>
  )
}
