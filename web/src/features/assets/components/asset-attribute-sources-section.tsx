'use client'

/**
 * Where an asset's values come from (RFC-069): for criticality, owner,
 * exposure and data classification, the source that decides the value, when
 * it saw it, and every other source's value with why it does not decide. A
 * person can set and lock a value, or release a lock so the sources decide
 * again. Used by every asset detail surface (the detail sheet and
 * /assets/{id}).
 */

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
  conflictText,
  decidedByText,
  displayValue,
  type AttributeSources,
  type TrackedAttribute,
} from '../lib/attribute-sources'

const NOT_SET = '__not_set__'

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
  const [value, setValue] = useState(current)
  const options = ATTRIBUTE_VALUES[attr]
  return (
    <div className="flex flex-wrap items-center gap-2">
      {options ? (
        <Select
          value={value === '' ? NOT_SET : value}
          onValueChange={(v) => setValue(v === NOT_SET ? '' : v)}
        >
          <SelectTrigger className="h-7 w-44" aria-label={`${ATTRIBUTE_LABEL[attr]} value`}>
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            {options.map((o) => (
              <SelectItem key={o || NOT_SET} value={o || NOT_SET}>
                {displayValue(o)}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      ) : (
        <Input
          className="h-7 w-56"
          value={value}
          maxLength={500}
          aria-label={`${ATTRIBUTE_LABEL[attr]} value`}
          onChange={(e) => setValue(e.target.value)}
        />
      )}
      <Button size="sm" className="h-7" disabled={saving} onClick={() => onLock(value)}>
        {saving ? (
          <Loader2 className="me-1 h-3 w-3 animate-spin" />
        ) : (
          <Lock className="me-1 h-3 w-3" />
        )}
        Set and lock
      </Button>
      <Button size="sm" variant="ghost" className="h-7" onClick={onCancel}>
        Cancel
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
  const [editing, setEditing] = useState(false)
  const conflict = conflictText(a)
  const others = a.sources.filter((s) => s.status !== 'winner')
  return (
    <li className="space-y-1.5 py-2" aria-label={ATTRIBUTE_LABEL[a.attribute]}>
      <div className="flex min-w-0 flex-wrap items-center gap-2">
        <span className="w-40 shrink-0 text-muted-foreground">{ATTRIBUTE_LABEL[a.attribute]}</span>
        <span className="font-medium break-all">{displayValue(a.value)}</span>
        {a.locked && (
          <Badge variant="outline" className="gap-1">
            <Lock className="h-3 w-3" aria-hidden />
            Locked
          </Badge>
        )}
        {conflict && (
          <Badge variant="outline" className="border-warning/40 bg-warning/10 text-warning">
            {conflict}
          </Badge>
        )}
      </div>
      <p className="text-xs text-muted-foreground sm:ps-42">
        {decidedByText(a)}
        {a.decided_by && (
          <>
            {' · seen '}
            <RelativeTime date={a.decided_by.observed_at} />
          </>
        )}
      </p>
      {others.length > 0 && (
        <ul
          className="space-y-0.5 text-xs sm:ps-42"
          aria-label={`Other sources of ${ATTRIBUTE_LABEL[a.attribute]}`}
        >
          {others.map((s) => (
            <li
              key={`${s.kind}-${s.name}`}
              className={cn(
                'flex flex-wrap gap-x-2',
                s.status === 'outranked' ? 'text-foreground' : 'text-muted-foreground'
              )}
              title={SOURCE_STATUS_HINT[s.status]}
            >
              <span>
                {SOURCE_KIND_LABEL[s.kind]}
                {s.name ? ` (${s.name})` : ''}
              </span>
              <span className="break-all">says {displayValue(s.value)}</span>
              <span>
                · {SOURCE_STATUS_LABEL[s.status]}, seen <RelativeTime date={s.observed_at} />
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
                {a.locked ? 'Change locked value' : 'Set and lock'}
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
                  Release lock
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
  const { data, error, isLoading, mutate } = useAttributeSources(assetId)
  const { lock, release, saving } = useAttributeLock(assetId)
  const { can } = usePermissions()
  const canWrite = can(Permission.AssetsWrite)

  const onLock = async (attr: TrackedAttribute, value: string) => {
    try {
      await lock(attr, value)
      await mutate()
      toast.success(`${ATTRIBUTE_LABEL[attr]} locked`)
      return true
    } catch (e) {
      toast.error(e instanceof Error ? e.message : 'Could not lock the value')
      return false
    }
  }
  const onRelease = async (attr: TrackedAttribute) => {
    try {
      await release(attr)
      await mutate()
      toast.success(`${ATTRIBUTE_LABEL[attr]} is decided by its sources again`)
    } catch (e) {
      toast.error(e instanceof Error ? e.message : 'Could not release the lock')
    }
  }

  return (
    <DetailSection title="Where values come from" icon={GitMerge}>
      {isLoading ? (
        <div className="space-y-2">
          <Skeleton className="h-5 w-1/2" />
          <Skeleton className="h-5 w-2/3" />
        </div>
      ) : error ? (
        <ErrorState title="value sources" error={error} onRetry={() => mutate()} />
      ) : data ? (
        <div className="space-y-2 text-sm">
          <p className="text-xs text-muted-foreground">
            Each value comes from the source your organization trusts most for it, and among equal
            sources from the one that saw the asset last. A locked value stays until it is released.
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
