'use client'

/**
 * The finding page's "How we found this" section: the story timeline of the
 * finding (scope entry, the assets it was found under, the scans and
 * sources that reported it). The API answers 404 for a finding the viewer
 * may not read: the section hides (no oracle). A finding with nothing to
 * tell (entered by a person, no asset) shows no section.
 */

import { Route } from 'lucide-react'
import { Skeleton } from '@/components/ui/skeleton'
import { useTranslation } from '@/context/i18n-provider'
import { DetailSection } from '@/features/shared/components/detail-sheet'
import { useSettleSignal } from '@/features/shared/components/settle-group'
import {
  SectionLoadError,
  isLoadFailure,
} from '@/features/findings/components/detail/section-load-error'
import { useStory } from '../hooks/use-story'
import { storyIsEmpty } from '../lib/story'
import { StoryTimeline } from './story-timeline'

export function FindingHowWeFoundThis({
  findingId,
  className,
}: {
  findingId: string
  className?: string
}) {
  const { t } = useTranslation()
  const { story, error, isLoading, mutate } = useStory('finding', findingId)
  useSettleSignal(isLoading)

  if (isLoading) {
    return (
      <div className={className}>
        <Skeleton className="h-5 w-1/3" />
        <Skeleton className="mt-2 h-5 w-2/3" />
      </div>
    )
  }
  if (isLoadFailure(error)) {
    return (
      <SectionLoadError
        title={t('exploration.story.loadTitle', 'how this was found')}
        onRetry={() => void mutate()}
        className={className}
      />
    )
  }
  if (error || !story || storyIsEmpty(story)) return null
  return (
    <DetailSection
      title={t('exploration.story.title', 'How we found this')}
      icon={Route}
      className={className}
    >
      <StoryTimeline story={story} />
    </DetailSection>
  )
}
