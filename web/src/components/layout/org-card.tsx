'use client'

/**
 * The organization card: what opens from the sidebar's context row.
 *
 * It always opens, even with one organization and no way to create another,
 * because it is where a member finds their role in the organization, how many
 * members it has and its ID. Top to bottom: the organization,
 * its details (role, members, ID), the API keys link, the other organizations
 * (only with more than one), "Create organization" (only when the server
 * allows self-service creation) and who is signed in.
 *
 * Never shows an API key: `oct_` keys are per user, hashed and shown once, so
 * the card only links to the API keys page.
 */

import * as React from 'react'
import Link from '@/components/link'
import { ArrowRight, Check, Copy, Loader2, Plus } from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Separator } from '@/components/ui/separator'
import { Skeleton } from '@/components/ui/skeleton'
import { useTranslation } from '@/context/i18n-provider'
import { copyToClipboard } from '@/lib/clipboard'
import { cn } from '@/lib/utils'
import { Input } from '@/components/ui/input'
import { orgInitials } from './org-initials'
import { PHONE_TOUCH_SQUARE } from './header-controls'
import { blockedReasonText, formatShortDate } from '@/features/organization/lib/external-access'

export { orgInitials }

export interface OrgCardOrganization {
  id: string
  name: string
  role?: string
  /** The user is an external member there (api RFC-058). */
  external?: boolean
  /** When the user's access there ends. */
  accessExpiresAt?: string
  /** Why it cannot be opened now (blocked_reason); the row is disabled. */
  blockedReason?: string
}

/** Above this many organizations the list gets a search box. */
export const ORG_SEARCH_THRESHOLD = 7

export interface OrgCardLink {
  label: string
  url: string
}

export interface OrgCardProps {
  current: { id: string; name: string; role?: string }
  /** Every organization the user belongs to, the current one included. */
  organizations: OrgCardOrganization[]
  /** Members settings page, when the user may open it (and so read the count). */
  membersLink?: OrgCardLink
  memberCount?: number
  memberCountLoading?: boolean
  /** API keys settings page, when the user may open it. */
  apiKeysLink?: OrgCardLink
  canCreate: boolean
  email?: string
  /** A switch is in progress (or the app is still bootstrapping). */
  isSwitching: boolean
  onSwitch: (organizationId: string) => void
  onCreate: () => void
  /** Called when a link inside the card is followed. */
  onNavigate: () => void
}

function capitalize(value: string): string {
  return value ? value[0].toUpperCase() + value.slice(1) : value
}

/** Translated role names, falling back to the raw value capitalized. */
export function useOrgLabels() {
  const { t } = useTranslation()
  return React.useMemo(
    () => ({
      role: (role?: string) => (role ? t(`org.role.${role}`, capitalize(role)) : ''),
    }),
    [t]
  )
}

/**
 * Initials on a neutral tile, so each organization is recognisable in the
 * list (a decorative icon cycled by index told the user nothing).
 */
function OrgAvatar({ name, size = 'md' }: { name: string; size?: 'sm' | 'md' }) {
  return (
    <span
      aria-hidden
      className={cn(
        'flex shrink-0 items-center justify-center rounded-md bg-muted font-semibold text-foreground ring-1 ring-border',
        size === 'md' ? 'size-9 text-xs' : 'size-6 text-[10px]'
      )}
    >
      {orgInitials(name)}
    </span>
  )
}

function DetailRow({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    // 44 on the phone: the row holds its link's 44 px touch area.
    <div className="flex min-h-7 items-center justify-between gap-3 text-body max-md:min-h-11">
      <dt className="shrink-0 text-muted-foreground">{label}</dt>
      <dd className="min-w-0 text-end">{children}</dd>
    </div>
  )
}

function CopyIdButton({ value }: { value: string }) {
  const { t } = useTranslation()
  const [state, setState] = React.useState<'idle' | 'copied' | 'failed'>('idle')

  React.useEffect(() => {
    if (state === 'idle') return
    const timer = window.setTimeout(() => setState('idle'), 2000)
    return () => window.clearTimeout(timer)
  }, [state])

  return (
    <>
      <Button
        type="button"
        variant="ghost"
        size="sm"
        // Phone: a 36 px square (icon 16, the check mark says "copied") with
        // a 44 x 44 touch area.
        className={cn(
          'h-7 shrink-0 gap-1.5 px-2 text-cap',
          'max-md:size-control-touch max-md:px-0 max-md:[&_svg]:size-4',
          PHONE_TOUCH_SQUARE
        )}
        aria-label={t('org.copyId', 'Copy organization ID')}
        onClick={async () => setState((await copyToClipboard(value)) ? 'copied' : 'failed')}
      >
        {state === 'copied' ? (
          <Check className="size-3.5 text-success" aria-hidden />
        ) : (
          <Copy className="size-3.5" aria-hidden />
        )}
        <span aria-hidden className="max-md:hidden">
          {state === 'copied' ? t('org.copied', 'Copied') : null}
        </span>
      </Button>
      <span role="status" aria-live="polite" className="sr-only">
        {state === 'copied'
          ? t('org.copied', 'Copied')
          : state === 'failed'
            ? t('org.copyFailed', 'Could not copy the organization ID')
            : ''}
      </span>
    </>
  )
}

/** Arrow keys move between the organizations; Enter or Space switches. */
function focusSibling(event: React.KeyboardEvent<HTMLUListElement>) {
  const keys = ['ArrowDown', 'ArrowUp', 'Home', 'End']
  if (!keys.includes(event.key)) return
  const buttons = Array.from(event.currentTarget.querySelectorAll<HTMLButtonElement>('button'))
  if (buttons.length === 0) return
  const index = buttons.indexOf(document.activeElement as HTMLButtonElement)
  let next = index
  if (event.key === 'ArrowDown') next = index < 0 ? 0 : (index + 1) % buttons.length
  if (event.key === 'ArrowUp') next = index <= 0 ? buttons.length - 1 : index - 1
  if (event.key === 'Home') next = 0
  if (event.key === 'End') next = buttons.length - 1
  event.preventDefault()
  buttons[next]?.focus()
}

/** Menu rows of the panel: 32 px, 44 on the phone (shell package D12). */
const ROW_LINK_CLASS =
  'flex h-8 max-md:h-11 w-full items-center gap-2 rounded-md px-2 text-body outline-hidden transition-colors hover:bg-accent hover:text-accent-foreground focus-visible:ring-2 focus-visible:ring-ring disabled:pointer-events-none disabled:opacity-50'

export function OrgCard({
  current,
  organizations,
  membersLink,
  memberCount,
  memberCountLoading,
  apiKeysLink,
  canCreate,
  email,
  isSwitching,
  onSwitch,
  onCreate,
  onNavigate,
}: OrgCardProps) {
  const { t } = useTranslation()
  const labels = useOrgLabels()
  const others = organizations.length > 1
  const [query, setQuery] = React.useState('')
  const searchable = organizations.length > ORG_SEARCH_THRESHOLD
  const shown = React.useMemo(() => {
    const q = query.trim().toLowerCase()
    return q ? organizations.filter((o) => o.name.toLowerCase().includes(q)) : organizations
  }, [organizations, query])
  const role = labels.role(current.role)

  const memberCountText =
    memberCount === undefined
      ? ''
      : memberCount === 1
        ? t('org.memberCount.one', '1 member')
        : t('org.memberCount.other', '{count} members', { count: memberCount })

  return (
    <div className="flex flex-col" data-testid="org-card">
      {/* 1. The organization */}
      <div className="flex items-center gap-3 p-3">
        <OrgAvatar name={current.name} />
        <div className="min-w-0 flex-1">
          <p className="truncate text-sm font-semibold" title={current.name}>
            {current.name}
          </p>
        </div>
      </div>

      <dl className="space-y-0.5 px-3 pb-3">
        {role && <DetailRow label={t('org.role', 'Your role')}>{role}</DetailRow>}
        {membersLink && (
          <DetailRow label={membersLink.label}>
            {memberCountLoading ? (
              <Skeleton className="ms-auto h-4 w-20" />
            ) : memberCount !== undefined ? (
              <Link
                href={membersLink.url}
                prefetch={false}
                onClick={onNavigate}
                // Phone: the text keeps its size; an invisible 44 px touch area.
                className="relative tabular-nums underline-offset-4 hover:underline focus-visible:underline focus-visible:outline-hidden max-md:after:absolute max-md:after:inset-x-0 max-md:after:top-1/2 max-md:after:h-touch-target max-md:after:min-w-touch-target max-md:after:-translate-y-1/2"
                data-testid="org-card-members"
              >
                {memberCountText}
              </Link>
            ) : null}
          </DetailRow>
        )}
        {/* 2. Organization ID: the label row carries the copy button, the
            full value gets its own line in the foreground colour (mono as an
            identifier, style contract section 5). */}
        <div className="pt-1">
          <div className="flex items-center justify-between gap-3">
            <dt className="text-sm text-muted-foreground">{t('org.id', 'Organization ID')}</dt>
            <CopyIdButton value={current.id} />
          </div>
          <dd
            className="font-mono text-xs break-all text-foreground select-all"
            data-testid="org-card-id"
          >
            {current.id}
          </dd>
        </div>
      </dl>

      {/* 3. API keys: a link to the page, never a key. */}
      {apiKeysLink && (
        <>
          <Separator />
          <div className="p-1">
            <Link
              href={apiKeysLink.url}
              prefetch={false}
              onClick={onNavigate}
              className={ROW_LINK_CLASS}
              data-testid="org-card-api-keys"
            >
              <span className="flex-1">{apiKeysLink.label}</span>
              <ArrowRight className="size-4 text-muted-foreground rtl:rotate-180" aria-hidden />
            </Link>
          </div>
        </>
      )}

      {/* 4. Other organizations */}
      {others && (
        <>
          <Separator />
          <div className="p-1">
            <p id="org-card-switch" className="px-2 pt-1.5 pb-1 text-xs text-muted-foreground">
              {t('org.switch', 'Switch organization')}
            </p>
            {searchable && (
              <div className="px-1 pb-1">
                <Input
                  type="search"
                  value={query}
                  onChange={(e) => setQuery(e.target.value)}
                  placeholder={t('org.search', 'Find an organization')}
                  aria-label={t('org.search', 'Find an organization')}
                  data-testid="org-card-search"
                />
              </div>
            )}
            {shown.length === 0 && (
              <p className="px-2 py-2 text-xs text-muted-foreground">
                {t('org.noMatch', 'No organization matches')}
              </p>
            )}
            <ul
              aria-labelledby="org-card-switch"
              onKeyDown={focusSibling}
              className={cn(searchable && 'max-h-72 overflow-y-auto')}
            >
              {shown.map((org) => {
                const active = org.id === current.id
                const blocked = !active && !!org.blockedReason
                const reason = blocked ? blockedReasonText(org.blockedReason) : ''
                const ends =
                  org.accessExpiresAt && !blocked
                    ? t('org.accessEnds', 'Access ends {date}', {
                        date: formatShortDate(org.accessExpiresAt),
                      })
                    : ''
                return (
                  <li key={org.id}>
                    <button
                      type="button"
                      className={cn(
                        ROW_LINK_CLASS,
                        'h-auto min-h-9 py-1 max-md:h-auto max-md:min-h-11',
                        active && 'bg-accent/60'
                      )}
                      aria-current={active ? 'true' : undefined}
                      aria-disabled={blocked || undefined}
                      aria-describedby={reason || ends ? `org-row-note-${org.id}` : undefined}
                      disabled={isSwitching || blocked}
                      onClick={() => (active || blocked ? undefined : onSwitch(org.id))}
                      data-testid="org-card-switch-item"
                      data-blocked={blocked || undefined}
                    >
                      <OrgAvatar name={org.name} size="sm" />
                      <span className="flex min-w-0 flex-1 flex-col text-start">
                        <span className="truncate">{org.name}</span>
                        {(reason || ends) && (
                          <span
                            id={`org-row-note-${org.id}`}
                            className={cn(
                              'truncate text-[11px]',
                              blocked ? 'text-destructive' : 'text-muted-foreground'
                            )}
                            data-testid="org-card-row-note"
                          >
                            {reason || ends}
                          </span>
                        )}
                      </span>
                      {org.external && (
                        <Badge
                          variant="outline"
                          className="h-5 shrink-0 px-1.5 text-[10px] font-normal"
                          data-testid="org-card-external"
                        >
                          {t('org.external', 'External')}
                        </Badge>
                      )}
                      {org.role && (
                        <span className="shrink-0 text-xs text-muted-foreground">
                          {labels.role(org.role)}
                        </span>
                      )}
                      <span className="flex size-4 shrink-0 items-center justify-center">
                        {active &&
                          (isSwitching ? (
                            <Loader2 className="size-4 animate-spin" aria-hidden />
                          ) : (
                            <Check className="size-4 text-primary" aria-hidden />
                          ))}
                      </span>
                    </button>
                  </li>
                )
              })}
            </ul>
          </div>
        </>
      )}

      {/* 5. Create organization: only when the server allows it. */}
      {canCreate && (
        <>
          <Separator />
          <div className="p-1">
            <button type="button" className={ROW_LINK_CLASS} onClick={onCreate}>
              <Plus className="size-4 text-muted-foreground" aria-hidden />
              <span className="flex-1 text-start">{t('org.create', 'Create organization')}</span>
            </button>
          </div>
        </>
      )}

      {/* 6. Who is signed in */}
      {email && (
        <>
          <Separator />
          <p className="truncate px-3 py-2.5 text-xs text-muted-foreground" title={email}>
            {t('org.signedInAs', 'Signed in as')}{' '}
            <span className="text-foreground" data-testid="org-card-email">
              {email}
            </span>
          </p>
        </>
      )}
    </div>
  )
}
