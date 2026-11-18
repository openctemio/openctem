'use client'

import React from 'react'
import { Clock, ClockArrowDown } from 'lucide-react'
import { toast } from 'sonner'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogBody,
} from '@/components/ui/dialog'
import { getErrorMessage } from '@/lib/api/error-handler'
import { useTranslation } from '@/context/i18n-provider'
import { SNOOZE_PRESETS, MIN_THRESHOLD_DAYS, MAX_THRESHOLD_DAYS } from '../types'
import { snoozeAssetLifecycle, unsnoozeAssetLifecycle } from '../api'

interface LifecycleSnoozeOptions {
  assetID: string
  /**
   * True when this asset currently has a snooze active. Drives
   * the label and the presence of the Unsnooze option.
   */
  isSnoozed?: boolean
  /**
   * True when the asset is currently flagged stale or inactive —
   * in that case the menu surfaces the "reactivate while snoozing"
   * shortcut, which is the typical operator flow for a false
   * positive.
   */
  isStaleOrInactive?: boolean
  /**
   * Called after a successful snooze / unsnooze so the parent can
   * refetch the asset row and re-render the badge.
   */
  onUpdated?: () => void
}

interface LifecycleSnoozeMenuProps extends LifecycleSnoozeOptions {
  /**
   * Optional class for the trigger button.
   */
  className?: string
}

/**
 * The snooze of one asset's lifecycle worker: the preset durations, the
 * custom-days dialog and clearing the snooze. `LifecycleSnoozeMenu` (a
 * button with its own menu) and an asset page's More menu (a submenu) both
 * run it, so the two offer the same choices with the same requests.
 */
export function useLifecycleSnooze({
  assetID,
  isSnoozed,
  isStaleOrInactive,
  onUpdated,
}: LifecycleSnoozeOptions) {
  const { t } = useTranslation()
  const [customOpen, setCustomOpen] = React.useState(false)
  const [customDays, setCustomDays] = React.useState('30')
  const [submitting, setSubmitting] = React.useState(false)

  const snooze = React.useCallback(
    async (days: number) => {
      try {
        setSubmitting(true)
        await snoozeAssetLifecycle(assetID, {
          days,
          reactivate: !!isStaleOrInactive,
        })
        toast.success(
          isStaleOrInactive
            ? t('assets.snooze.reactivated', 'Reactivated and snoozed for {days} days.', { days })
            : t('assets.snooze.snoozed', 'Lifecycle worker snoozed for {days} days.', { days })
        )
        onUpdated?.()
      } catch (err) {
        toast.error(getErrorMessage(err))
      } finally {
        setSubmitting(false)
      }
    },
    [assetID, isStaleOrInactive, onUpdated, t]
  )

  const handleCustomSubmit = React.useCallback(async () => {
    const days = parseInt(customDays, 10)
    if (!Number.isFinite(days) || days < 1 || days > MAX_THRESHOLD_DAYS) {
      toast.error(
        t('assets.snooze.invalidDays', 'Enter a whole number between 1 and {max}.', {
          max: MAX_THRESHOLD_DAYS,
        })
      )
      return
    }
    await snooze(days)
    setCustomOpen(false)
  }, [customDays, snooze, t])

  const unsnooze = React.useCallback(async () => {
    try {
      setSubmitting(true)
      await unsnoozeAssetLifecycle(assetID)
      toast.success(t('assets.snooze.cleared', 'Lifecycle snooze cleared.'))
      onUpdated?.()
    } catch (err) {
      toast.error(getErrorMessage(err))
    } finally {
      setSubmitting(false)
    }
  }, [assetID, onUpdated, t])

  const presets = SNOOZE_PRESETS.map((preset) => ({
    days: preset.days,
    label: t(`assets.snooze.preset.${preset.days}`, preset.label),
  }))

  const dialog = (
    <Dialog open={customOpen} onOpenChange={setCustomOpen}>
      <DialogContent size="sm">
        <DialogHeader>
          <DialogTitle>{t('assets.snooze.customTitle', 'Custom snooze duration')}</DialogTitle>
          <DialogDescription>
            {t(
              'assets.snooze.customHint',
              'Between {min} and {max} days. The lifecycle worker skips this asset until the snooze expires.',
              { min: MIN_THRESHOLD_DAYS, max: MAX_THRESHOLD_DAYS }
            )}
          </DialogDescription>
        </DialogHeader>
        <DialogBody>
          <div className="space-y-2">
            <Label htmlFor="custom-days">{t('assets.snooze.days', 'Days')}</Label>
            <Input
              id="custom-days"
              type="number"
              min={MIN_THRESHOLD_DAYS}
              max={MAX_THRESHOLD_DAYS}
              value={customDays}
              onChange={(e) => setCustomDays(e.target.value)}
            />
          </div>
        </DialogBody>
        <DialogFooter>
          <Button variant="outline" onClick={() => setCustomOpen(false)}>
            {t('common.cancel', 'Cancel')}
          </Button>
          <Button
            onClick={() => {
              void handleCustomSubmit()
            }}
            disabled={submitting}
          >
            {t('assets.snooze.submit', 'Snooze')}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )

  return {
    submitting,
    isSnoozed: !!isSnoozed,
    /** The menu's heading: what a preset does for this asset now. */
    heading: isStaleOrInactive
      ? t('assets.snooze.reactivateFor', 'Reactivate and pause the worker for…')
      : t('assets.snooze.pauseFor', 'Pause the lifecycle worker for…'),
    presets,
    snooze,
    unsnooze,
    openCustom: () => setCustomOpen(true),
    dialog,
  }
}

/**
 * Snooze menu for a single asset. Operator picks a preset duration
 * (7 / 30 / 90 days / 1 year) or opens a custom-days dialog. When
 * the asset is currently stale/inactive the preset actions flag
 * `reactivate: true` so the worker does not immediately re-demote.
 */
export function LifecycleSnoozeMenu({ className, ...options }: LifecycleSnoozeMenuProps) {
  const { t } = useTranslation()
  const s = useLifecycleSnooze(options)

  return (
    <>
      <DropdownMenu>
        <DropdownMenuTrigger asChild>
          <Button variant="outline" size="sm" className={className} disabled={s.submitting}>
            {s.isSnoozed ? (
              <>
                <ClockArrowDown />
                {t('assets.snooze.isSnoozed', 'Snoozed')}
              </>
            ) : (
              <>
                <Clock />
                {t('assets.snooze.button', 'Snooze lifecycle')}
              </>
            )}
          </Button>
        </DropdownMenuTrigger>
        <DropdownMenuContent>
          <DropdownMenuLabel>{s.heading}</DropdownMenuLabel>
          <DropdownMenuSeparator />
          {s.presets.map((preset) => (
            <DropdownMenuItem
              key={preset.days}
              onSelect={() => {
                void s.snooze(preset.days)
              }}
            >
              {preset.label}
            </DropdownMenuItem>
          ))}
          <DropdownMenuItem
            onSelect={(e) => {
              e.preventDefault()
              s.openCustom()
            }}
          >
            {t('assets.snooze.custom', 'Custom…')}
          </DropdownMenuItem>
          {s.isSnoozed && (
            <>
              <DropdownMenuSeparator />
              <DropdownMenuItem
                onSelect={() => {
                  void s.unsnooze()
                }}
              >
                {t('assets.snooze.clear', 'Clear snooze')}
              </DropdownMenuItem>
            </>
          )}
        </DropdownMenuContent>
      </DropdownMenu>

      {s.dialog}
    </>
  )
}
