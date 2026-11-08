'use client'

/**
 * The asset's "Next steps" (api docs/architecture/exploration.md): at most
 * three steps the platform plans or took on this asset, each saying what
 * will be checked, because of which observation, and where it stands. "See
 * all" opens the Exploration page for the asset; "Ask" (scans:execute) opens
 * a catalog question. The API applies the caller's data scope; when the
 * list cannot be read the section hides.
 */

import { useState } from 'react'
import { Compass, Plus } from 'lucide-react'
import Link from '@/components/link'
import { Button } from '@/components/ui/button'
import { Skeleton } from '@/components/ui/skeleton'
import { useTranslation } from '@/context/i18n-provider'
import { DetailSection } from '@/features/shared'
import { useSettleSignal } from '@/features/shared/components/settle-group'
import { Can, Permission } from '@/lib/permissions'
import { useAssetLeads } from '../hooks/use-leads'
import { explorationHref, leadQuestion, leadStatusText, reasonLabel } from '../lib/leads'
import { AskLeadDialog } from './ask-lead-dialog'

export const NEXT_STEPS_LIMIT = 3

export function AssetNextSteps({ assetId }: { assetId: string }) {
  const { t, locale } = useTranslation()
  const { leads, error, isLoading, mutate } = useAssetLeads(assetId, NEXT_STEPS_LIMIT)
  useSettleSignal(isLoading)
  const [asking, setAsking] = useState(false)
  const day = (iso: string) => {
    try {
      return new Intl.DateTimeFormat(locale, { dateStyle: 'medium' }).format(new Date(iso))
    } catch {
      return iso.slice(0, 10)
    }
  }

  if (error) return null
  return (
    <DetailSection
      title={t('exploration.card.title', 'Next steps')}
      icon={Compass}
      actions={
        <>
          <Can permission={Permission.ScansExecute}>
            <Button variant="ghost" size="sm" onClick={() => setAsking(true)}>
              <Plus className="me-1 h-3.5 w-3.5" aria-hidden />
              {t('exploration.card.ask', 'Ask')}
            </Button>
          </Can>
          {leads.length > 0 && (
            <Button variant="ghost" size="sm" asChild>
              <Link href={explorationHref(assetId)}>{t('exploration.card.seeAll', 'See all')}</Link>
            </Button>
          )}
        </>
      }
    >
      {isLoading ? (
        <div className="space-y-2">
          <Skeleton className="h-5 w-2/3" />
          <Skeleton className="h-5 w-1/2" />
        </div>
      ) : leads.length === 0 ? (
        <p className="text-sm text-muted-foreground" data-testid="next-steps-empty">
          {t('exploration.card.empty', 'No next step is planned for this asset.')}
        </p>
      ) : (
        <ul className="space-y-2 text-sm" data-testid="next-steps">
          {leads.slice(0, NEXT_STEPS_LIMIT).map((l) => (
            <li key={l.id} className="min-w-0 space-y-0.5">
              <Link
                href={`${explorationHref(assetId)}&lead=${encodeURIComponent(l.id)}`}
                className="break-words font-medium hover:underline"
              >
                {leadQuestion(t, l.type)}
              </Link>
              <p className="text-meta text-muted-foreground">
                {t('exploration.card.because', 'Because: {reason}', {
                  reason: reasonLabel(t, l.reason_code),
                })}
              </p>
              <p className="text-meta" data-testid="next-step-status">
                {leadStatusText(t, l, day)}
              </p>
            </li>
          ))}
        </ul>
      )}
      <AskLeadDialog
        assetId={assetId}
        open={asking}
        onOpenChange={setAsking}
        onAsked={() => void mutate()}
      />
    </DetailSection>
  )
}
