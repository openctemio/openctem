'use client'

/**
 * Where an asset's values come from (RFC-069): for criticality, owner,
 * exposure and data classification, the source that decides the value, when
 * it saw it, and every other source's value with why it does not decide. A
 * person can set and lock a value, or release a lock so the sources decide
 * again. Used by every asset detail surface (the detail sheet and
 * /assets/{id}).
 */

import { useSettleSignal } from '@/features/shared/components/settle-group'
import { useState } from 'react'
import { GitMerge, Loader2, Lock, LockOpen } from 'lucide-react'
import { toast } from 'sonner'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { Skeleton } from '@/components/ui/skeleton'
import { useTranslation } from '@/context/i18n-provider'
import { DetailSection, ErrorState, RelativeTime } from '@/features/shared'
import { usePermissions, Permission } from '@/lib/permissions'
import { cn } from '@/lib/utils'
import { useAttributeLock, useAttributeSources } from '../hooks/use-attribute-sources'
import {
  ATTRIBUTE_LABEL,
  ATTRIBUTE_VALUES,
  SOURCE_KIND_LABEL,
  SOURCE_STATUS_HINT,
  SOURCE_STATUS_LABEL,
  type AttributeSources,
  type SourceKind,
  type SourceStatus,
  type TrackedAttribute,
} from '../lib/attribute-sources'

const NOT_SET = '__not_set__'

type T = ReturnType<typeof useTranslation>['t']

// Every word of the section through the catalog (the lib keeps the English
// fallbacks): a vi page read "Owner reference", "Not set" and the source names
// in English.
const attrLabel = (t: T, a: TrackedAttribute) =>
  t(`assetSources.attribute.${a}`, ATTRIBUTE_LABEL[a])
const valueText = (t: T, v: string) =>
  v.trim() === '' ? t('assets.attrSources.notSet', 'Not set') : v
const kindText = (t: T, k: SourceKind) => t(`assets.attrSources.kind.${k}`, SOURCE_KIND_LABEL[k])
const statusText = (t: T, s: SourceStatus) =>
  t(`assets.attrSources.status.${s}`, SOURCE_STATUS_LABEL[s])
const statusHint = (t: T, s: SourceStatus) =>
  t(`assets.attrSources.statusHint.${s}`, SOURCE_STATUS_HINT[s])

function decidedText(t: T, a: AttributeSources): string {
  if (a.locked)
    return t('assets.attrSources.decided.locked', 'Set by a person, locked until released')
  const w = a.decided_by
  if (!w) {
    return a.sources.length === 0
      ? t('assets.attrSources.decided.none', 'No source has reported it')
      : t('assets.attrSources.decided.kept', 'No trusted, current source: the value is kept')
  }
  return w.name ? `${kindText(t, w.kind)} (${w.name})` : kindText(t, w.kind)
}

function conflictLabel(t: T, a: AttributeSources): string | null {
  if (!a.conflict) return null
  const counted = a.sources.filter((s) => s.status === 'winner' || s.status === 'outranked')
  const n = new Set(counted.map((s) => s.value)).size
  return t(
    'assets.attrSources.disagree',
    '{n, plural, one {# source disagrees} other {# sources disagree}}',
    { n }
  )
}

function LockEditor({
  attr,
  current,
  saving,
  onLock,
  onCancel,
}: {
  attr: TrackedAttribute
  current: string
  saving: boolean
  onLock: (value: string) => void
  onCancel: () => void
}) {
  const { t } = useTranslation()
  const [value, setValue] = useState(current)
  const options = ATTRIBUTE_VALUES[attr]
  return (
    <div className="flex flex-wrap items-center gap-2">
      {options ? (
        <Select
          value={value === '' ? NOT_SET : value}
          onValueChange={(v) => setValue(v === NOT_SET ? '' : v)}
        >
          <SelectTrigger
            className="h-7 w-44"
            aria-label={t('assets.attrSources.valueAria', '{attribute} value', {
              attribute: attrLabel(t, attr),
            })}
          >
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            {options.map((o) => (
              <SelectItem key={o || NOT_SET} value={o || NOT_SET}>
                {valueText(t, o)}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      ) : (
        <Input
          className="h-7 w-56"
          value={value}
          maxLength={500}
          aria-label={t('assets.attrSources.valueAria', '{attribute} value', {
            attribute: attrLabel(t, attr),
          })}
          onChange={(e) => setValue(e.target.value)}
        />
      )}
      <Button size="sm" className="h-7" disabled={saving} onClick={() => onLock(value)}>
        {saving ? (
          <Loader2 className="me-1 h-3 w-3 animate-spin" />
        ) : (
          <Lock className="me-1 h-3 w-3" />
        )}
        {t('assets.attrSources.setAndLock', 'Set and lock')}
      </Button>
      <Button size="sm" variant="ghost" className="h-7" onClick={onCancel}>
        {t('common.cancel', 'Cancel')}
      </Button>
    </div>
  )
}

function AttributeRow({
  a,
  canWrite,
  saving,
  onLock,
  onRelease,
}: {
  a: AttributeSources
  canWrite: boolean
  saving: boolean
  onLock: (attr: TrackedAttribute, value: string) => Promise<boolean>
  onRelease: (attr: TrackedAttribute) => void
}) {
  const { t } = useTranslation()
  const [editing, setEditing] = useState(false)
  const conflict = conflictLabel(t, a)
  const others = a.sources.filter((s) => s.status !== 'winner')
  return (
    <li className="space-y-1.5 py-2" aria-label={attrLabel(t, a.attribute)}>
      <div className="flex min-w-0 flex-wrap items-center gap-2">
        <span className="w-40 shrink-0 text-muted-foreground">{attrLabel(t, a.attribute)}</span>
        <span className="font-medium break-words">{valueText(t, a.value)}</span>
        {a.locked && (
          <Badge variant="outline" className="gap-1">
            <Lock className="h-3 w-3" aria-hidden />
            {t('assets.attrSources.locked', 'Locked')}
          </Badge>
        )}
        {conflict && (
          <Badge variant="outline" className="border-warning/40 bg-warning/10 text-warning">
            {conflict}
          </Badge>
        )}
      </div>
      <p className="text-xs text-muted-foreground sm:ps-42">
        {decidedText(t, a)}
        {a.decided_by && (
          <>
            {t('assets.attrSources.seen', ', seen ')}
            <RelativeTime date={a.decided_by.observed_at} />
          </>
        )}
      </p>
      {others.length > 0 && (
        <ul
          className="space-y-0.5 text-xs sm:ps-42"
          aria-label={t('assets.attrSources.othersAria', 'Other sources of {attribute}', {
            attribute: attrLabel(t, a.attribute),
          })}
        >
          {others.map((s) => (
            <li
              key={`${s.kind}-${s.name}`}
              className={cn(
                'flex flex-wrap gap-x-2',
                s.status === 'outranked' ? 'text-foreground' : 'text-muted-foreground'
              )}
              title={statusHint(t, s.status)}
            >
              <span>
                {kindText(t, s.kind)}
                {s.name ? ` (${s.name})` : ''}
              </span>
              <span className="break-words">
                {t('assets.attrSources.says', 'says {value}', { value: valueText(t, s.value) })}
              </span>
              <span>
                , {statusText(t, s.status)}, {t('assets.attrSources.seenShort', 'seen')}{' '}
                <RelativeTime date={s.observed_at} />
              </span>
            </li>
          ))}
        </ul>
      )}
      {canWrite && (
        <div className="sm:ps-42">
          {editing ? (
            <LockEditor
              attr={a.attribute}
              current={a.value}
              saving={saving}
              onCancel={() => setEditing(false)}
              onLock={async (v) => {
                if (await onLock(a.attribute, v)) setEditing(false)
              }}
            />
          ) : (
            <div className="flex flex-wrap gap-2">
              <Button size="sm" variant="outline" className="h-7" onClick={() => setEditing(true)}>
                <Lock className="me-1 h-3 w-3" />
                {a.locked
                  ? t('assets.attrSources.changeLocked', 'Change locked value')
                  : t('assets.attrSources.setAndLock', 'Set and lock')}
              </Button>
              {a.locked && (
                <Button
                  size="sm"
                  variant="outline"
                  className="h-7"
                  disabled={saving}
                  onClick={() => onRelease(a.attribute)}
                >
                  <LockOpen className="me-1 h-3 w-3" />
                  {t('assets.attrSources.release', 'Release lock')}
                </Button>
              )}
            </div>
          )}
        </div>
      )}
    </li>
  )
}

/** Renders one DetailSection; place it inside a <DetailSections>. */
export function AssetAttributeSourcesSection({ assetId }: { assetId: string }) {
  const { t } = useTranslation()
  const { data, error, isLoading, mutate } = useAttributeSources(assetId)
  useSettleSignal(isLoading)
  const { lock, release, saving } = useAttributeLock(assetId)
  const { can } = usePermissions()
  const canWrite = can(Permission.AssetsWrite)

  const onLock = async (attr: TrackedAttribute, value: string) => {
    try {
      await lock(attr, value)
      await mutate()
      toast.success(
        t('assets.attrSources.lockedToast', '{attribute} locked', {
          attribute: attrLabel(t, attr),
        })
      )
      return true
    } catch (e) {
      toast.error(
        e instanceof Error
          ? e.message
          : t('assets.attrSources.lockFailed', 'Could not lock the value')
      )
      return false
    }
  }
  const onRelease = async (attr: TrackedAttribute) => {
    try {
      await release(attr)
      await mutate()
      toast.success(
        t('assets.attrSources.releasedToast', '{attribute} is decided by its sources again', {
          attribute: attrLabel(t, attr),
        })
      )
    } catch (e) {
      toast.error(
        e instanceof Error
          ? e.message
          : t('assets.attrSources.releaseFailed', 'Could not release the lock')
      )
    }
  }

  return (
    <DetailSection title={t('assets.attrSources.title', 'Where values come from')} icon={GitMerge}>
      {isLoading ? (
        <div className="space-y-2">
          <Skeleton className="h-5 w-1/2" />
          <Skeleton className="h-5 w-2/3" />
        </div>
      ) : error ? (
        <ErrorState
          title={t('assets.attrSources.errorTitle', 'value sources')}
          error={error}
          onRetry={() => mutate()}
        />
      ) : data ? (
        <div className="space-y-2 text-sm">
          <p className="text-xs text-muted-foreground">
            {t(
              'assets.attrSources.intro',
              'Each value comes from the source your organization trusts most for it, and among equal sources from the one that saw the asset last. A locked value stays until it is released.'
            )}
          </p>
          <ul className="divide-y">
            {data.attributes.map((a) => (
              <AttributeRow
                key={a.attribute}
                a={a}
                canWrite={canWrite}
                saving={saving}
                onLock={onLock}
                onRelease={onRelease}
              />
            ))}
          </ul>
        </div>
      ) : null}
    </DetailSection>
  )
}
