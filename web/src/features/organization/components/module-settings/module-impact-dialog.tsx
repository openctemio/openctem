'use client'

import { ConfirmDialog } from '@/components/confirm-dialog'
import { useTranslation } from '@/context/i18n-provider'
import { useFormatList } from '@/lib/format-list'
import type { ModulePlan } from '@/features/organization/lib/module-plan'
import { useModuleText } from './use-module-text'

export interface ModuleImpactDialogProps {
  open: boolean
  onOpenChange: (open: boolean) => void
  plan: ModulePlan
  /** Fallback names for module ids (API text). */
  apiNames: Record<string, string>
  saving?: boolean
  onConfirm: () => void
}

/**
 * The preview before a save that turns modules off, or turns on modules the
 * admin did not pick: which modules change and why, what stops, and that the
 * data is kept. Everything listed is saved together in one request.
 */
export function ModuleImpactDialog({
  open,
  onOpenChange,
  plan,
  apiNames,
  saving,
  onConfirm,
}: ModuleImpactDialogProps) {
  const { t } = useTranslation()
  const text = useModuleText()
  const formatList = useFormatList()
  const nameOf = (id: string) => text.name(id, apiNames[id])

  const entries = Object.entries(plan.changes)
  const chosenOff = entries.filter(([id, v]) => !v && !plan.offWith[id]).map(([id]) => id)
  const cascadeOff = entries.filter(([id, v]) => !v && plan.offWith[id]).map(([id]) => id)
  const chosenOn = entries.filter(([id, v]) => v && !plan.onWith[id]).map(([id]) => id)
  const cascadeOn = entries.filter(([id, v]) => v && plan.onWith[id]).map(([id]) => id)
  const offCount = chosenOff.length + cascadeOff.length
  const onCount = chosenOn.length + cascadeOn.length

  const title =
    offCount > 0 && onCount === 0
      ? t(
          'confirm.modules.offTitle',
          'Turn off {count, plural, one {# module} other {# modules}}?',
          {
            count: offCount,
          }
        )
      : offCount === 0
        ? t(
            'confirm.modules.onTitle',
            'Turn on {count, plural, one {# module} other {# modules}}?',
            {
              count: onCount,
            }
          )
        : t(
            'confirm.modules.mixedTitle',
            'Change {count, plural, one {# module} other {# modules}}?',
            { count: offCount + onCount }
          )

  const confirmText =
    offCount > 0 && onCount === 0
      ? cascadeOff.length > 0
        ? t('confirm.modules.offTogether', 'Turn off all {count} together', { count: offCount })
        : t(
            'confirm.modules.offConfirm',
            'Turn off {count, plural, one {# module} other {# modules}}',
            { count: offCount }
          )
      : offCount === 0
        ? t(
            'confirm.modules.onConfirm',
            'Turn on {count, plural, one {# module} other {# modules}}',
            { count: onCount }
          )
        : t(
            'confirm.modules.mixedConfirm',
            'Save {count, plural, one {# change} other {# changes}}',
            { count: offCount + onCount }
          )

  const desc =
    offCount > 0
      ? t(
          'confirm.modules.offDesc',
          'This applies to every member of this organization. The data is kept, and turning a module on again brings it back.'
        )
      : t(
          'confirm.modules.onDesc',
          'The modules you picked need these modules, so they turn on together.'
        )

  return (
    <ConfirmDialog
      open={open}
      onOpenChange={onOpenChange}
      title={title}
      desc={desc}
      confirmText={confirmText}
      destructive={offCount > 0}
      isLoading={saving}
      handleConfirm={onConfirm}
    >
      <div className="space-y-4 text-sm">
        {chosenOff.length > 0 && (
          <ImpactList
            heading={t('confirm.modules.turningOff', 'Turning off')}
            items={chosenOff.map((id) => ({ id, name: nameOf(id) }))}
          />
        )}
        {cascadeOff.length > 0 && (
          <ImpactList
            heading={t('confirm.modules.offWithHeading', 'Also turning off, because they need it')}
            items={cascadeOff.map((id) => ({
              id,
              name: nameOf(id),
              why: t('confirm.modules.needs', 'Needs {names}', {
                names: formatList(plan.offWith[id].map(nameOf)),
              }),
            }))}
          />
        )}
        {chosenOn.length > 0 && (
          <ImpactList
            heading={t('confirm.modules.turningOn', 'Turning on')}
            items={chosenOn.map((id) => ({ id, name: nameOf(id) }))}
          />
        )}
        {cascadeOn.length > 0 && (
          <ImpactList
            heading={t('confirm.modules.onWithHeading', 'Also turning on, because they are needed')}
            items={cascadeOn.map((id) => ({
              id,
              name: nameOf(id),
              why: t('confirm.modules.neededBy', 'Needed by {names}', {
                names: formatList(plan.onWith[id].map(nameOf)),
              }),
            }))}
          />
        )}
        {offCount > 0 && (
          <div>
            <h3 className="font-medium">{t('confirm.modules.stopsHeading', 'What stops')}</h3>
            <ul className="mt-1 list-disc space-y-0.5 ps-5 text-muted-foreground">
              <li>
                {t('confirm.modules.stopsPages', 'Their pages leave the menu and stop opening.')}
              </li>
              <li>
                {t(
                  'confirm.modules.stopsJobs',
                  'Their scheduled jobs, syncs and automations stop running.'
                )}
              </li>
              <li>
                {t(
                  'confirm.modules.stopsMcp',
                  'AI assistants connected over MCP lose the tools these modules provide.'
                )}
              </li>
            </ul>
          </div>
        )}
      </div>
    </ConfirmDialog>
  )
}

function ImpactList({
  heading,
  items,
}: {
  heading: string
  items: { id: string; name: string; why?: string }[]
}) {
  return (
    <div>
      <h3 className="font-medium">{heading}</h3>
      <ul className="mt-1 divide-y rounded-md border">
        {items.map((it) => (
          <li key={it.id} className="px-3 py-2">
            <div>{it.name}</div>
            {it.why && <div className="text-muted-foreground">{it.why}</div>}
          </li>
        ))}
      </ul>
    </div>
  )
}
