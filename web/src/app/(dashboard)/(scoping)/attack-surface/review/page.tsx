'use client'

/**
 * Attack surface › Review (research/117, research/274): the scope decisions that still
 * need a person, one card each (addresses behind in-scope names, names found
 * outside every entry, confirmed assets no entry covers). Every row of the
 * attribution queue stays one click away ("Show all items") for audits and
 * the "Not ours" undo list (`?tab=rejected` opens it).
 */

import { List } from 'lucide-react'
import { Main } from '@/components/layout'
import { Button } from '@/components/ui/button'
import { PageHeader, PageStack } from '@/features/shared'
import {
  AttackSurfaceSectionTabs,
  EASMDecidePanel,
  EASMReviewQueue,
} from '@/features/attack-surface'
import { useTranslation } from '@/context/i18n-provider'
import { useUrlFilter } from '@/hooks/use-url-param'

export default function AttackSurfaceSuggestionsPage() {
  const { t } = useTranslation()
  const [all, setAll] = useUrlFilter('all', '0')
  const [tab, setTab] = useUrlFilter('tab', '')
  const [reason, setReason] = useUrlFilter('reason', '')
  // A deep link (?tab=, ?reason=) opens the list it filters; Hide closes it by
  // clearing all three, otherwise it would stay open.
  const showAll = all === '1' || tab !== '' || reason !== ''
  const hideAll = () => {
    setAll('0')
    setTab('')
    setReason('')
  }
  return (
    <Main>
      <PageStack>
        <PageHeader
          title={t('attackSurface.title', 'Attack surface')}
          description={t(
            'attackSurface.suggestions.description',
            'Names and addresses that need a person to decide whether they are yours. Nothing joins your scope until someone confirms it.'
          )}
        />
        <AttackSurfaceSectionTabs />
        <EASMDecidePanel />
        {showAll ? (
          <section
            aria-label={t('attackSurface.suggestions.allItems', 'All items')}
            className="space-y-3"
          >
            <div className="flex items-center justify-between gap-2">
              <h2 className="text-base font-semibold">
                {t('attackSurface.suggestions.allItems', 'All items')}
              </h2>
              <Button size="sm" variant="ghost" onClick={hideAll}>
                {t('attackSurface.suggestions.hideAll', 'Hide items')}
              </Button>
            </div>
            <EASMReviewQueue />
          </section>
        ) : (
          <Button size="sm" variant="outline" onClick={() => setAll('1')}>
            <List className="me-2 h-4 w-4" aria-hidden />
            {t('attackSurface.suggestions.showAll', 'Show all items')}
          </Button>
        )}
      </PageStack>
    </Main>
  )
}
