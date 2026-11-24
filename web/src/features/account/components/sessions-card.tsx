'use client'

import { useState } from 'react'
import { Globe, Loader2, LogOut, Monitor, Smartphone } from 'lucide-react'
import { toast } from 'sonner'

import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Skeleton } from '@/components/ui/skeleton'
import { ConfirmDialog } from '@/components/confirm-dialog'
import { EmptyState, SettingsSection } from '@/features/shared'
import { getErrorMessage } from '@/lib/api/error-handler'
import { formatDateSafe, formatRelative } from '@/lib/format-date'

import { RevokeApiKeysOption } from '@/features/auth/components/revoke-api-keys-option'
import { useRevokeAllSessions, useRevokeSession } from '../api/use-sessions'
import { describeUserAgent, type DeviceKind } from '../lib/user-agent'
import type { Session } from '../types/account.types'
import { useTranslation } from '@/context/i18n-provider'

const DEVICE_ICON: Record<DeviceKind, typeof Monitor> = {
  desktop: Monitor,
  mobile: Smartphone,
  other: Globe,
}

interface SessionsCardProps {
  sessions: Session[]
  isLoading: boolean
  onChanged: () => void
  /** API keys the person owns, for the "Also revoke API keys (N)" choice. */
  activeApiKeys?: number
}

/**
 * Active sign-ins of the current user. Signing a session out takes effect on
 * that device's next request.
 */
export function SessionsCard({ sessions, isLoading, onChanged, activeApiKeys }: SessionsCardProps) {
  const { t } = useTranslation()
  const { revokeSession, isRevoking } = useRevokeSession()
  const { revokeAllSessions, isRevoking: isRevokingAll } = useRevokeAllSessions()
  const [toRevoke, setToRevoke] = useState<Session | null>(null)
  const [confirmAll, setConfirmAll] = useState(false)
  const [revokeKeys, setRevokeKeys] = useState(true)

  const ordered = [...sessions].sort((a, b) =>
    a.is_current === b.is_current
      ? b.last_activity_at.localeCompare(a.last_activity_at)
      : a.is_current
        ? -1
        : 1
  )
  const others = sessions.filter((s) => !s.is_current)

  async function revokeOne() {
    if (!toRevoke) return
    try {
      await revokeSession(toRevoke.id)
      toast.success(t('account.sessions.revoked', 'Session signed out'))
      setToRevoke(null)
      onChanged()
    } catch (error) {
      toast.error(
        getErrorMessage(error, t('account.sessions.revokeFailed', 'Could not sign out the session'))
      )
    }
  }

  async function revokeOthers() {
    try {
      await revokeAllSessions(revokeKeys)
      toast.success(
        t(
          'account.sessions.revokedOthers',
          'Signed out of all other sessions. Connected apps were revoked.'
        )
      )
      setConfirmAll(false)
      onChanged()
    } catch (error) {
      toast.error(
        getErrorMessage(
          error,
          t('account.sessions.revokeOthersFailed', 'Could not sign out the other sessions')
        )
      )
    }
  }

  return (
    <SettingsSection
      framed
      id="sessions"
      className="scroll-mt-4"
      title={t('account.sessions.title', 'Sessions')}
      description={t('account.sessions.description', 'Devices signed in to your account.')}
      actions={
        others.length > 0 && (
          <Button variant="outline" onClick={() => setConfirmAll(true)}>
            <LogOut aria-hidden />
            {t('account.sessions.signOutOthers', 'Sign out all others')}
          </Button>
        )
      }
    >
      {isLoading ? (
        <div className="space-y-3">
          <Skeleton className="h-16 w-full" />
          <Skeleton className="h-16 w-full" />
        </div>
      ) : sessions.length === 0 ? (
        <EmptyState
          icon={Monitor}
          title={t('account.sessions.empty', 'No active sessions')}
          card={false}
        />
      ) : (
        <ul>
          {ordered.map((s) => {
            const d = describeUserAgent(s.user_agent)
            const Icon = DEVICE_ICON[d.kind]
            return (
              <li key={s.id} className="border-t border-border-subtle py-3.5">
                <div className="flex min-w-0 items-start gap-3">
                  <Icon className="mt-0.5 h-5 w-5 shrink-0 text-muted-foreground" />
                  <div className="min-w-0 flex-1 space-y-0.5">
                    {/* Sign out sits on the device line, so the details below keep
                          the full width on a phone. */}
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="font-medium">
                        {t('account.sessions.browserOn', '{browser} on {os}', {
                          browser:
                            d.browser === 'Unknown browser'
                              ? t('account.sessions.unknownBrowser', 'Unknown browser')
                              : d.browser,
                          os:
                            d.os === 'unknown device'
                              ? t('account.sessions.unknownDevice', 'unknown device')
                              : d.os,
                        })}
                      </span>
                      {s.is_current && (
                        <Badge variant="secondary">
                          {t('account.sessions.thisDevice', 'This device')}
                        </Badge>
                      )}
                      {!s.is_current && (
                        <Button
                          variant="ghost"
                          className="ms-auto shrink-0 text-destructive hover:text-destructive"
                          onClick={() => setToRevoke(s)}
                        >
                          {t('account.sessions.signOut', 'Sign out')}
                        </Button>
                      )}
                    </div>
                    <p className="text-sm text-muted-foreground">
                      {s.ip_address ? (
                        <span className="font-mono">{s.ip_address}</span>
                      ) : (
                        t('account.sessions.unknownIp', 'Unknown IP')
                      )}
                      {', '}
                      {t('account.sessions.signedIn', 'Signed in {date}', {
                        date: formatDateSafe(s.created_at),
                      })}
                      {', '}
                      {t('account.sessions.lastActive', 'Last active {when}', {
                        when: formatRelative(s.last_activity_at),
                      })}
                    </p>
                  </div>
                </div>
              </li>
            )
          })}
        </ul>
      )}

      <ConfirmDialog
        open={!!toRevoke}
        onOpenChange={(open) => !open && setToRevoke(null)}
        title={(() => {
          const d = toRevoke ? describeUserAgent(toRevoke.user_agent) : null
          return t('confirm.session.revokeTitle', 'Sign out {device}?', {
            device: d ? `${d.browser} / ${d.os}` : '',
          })
        })()}
        desc={t(
          'confirm.session.revokeDesc',
          'That device is signed out at once and has to sign in again.'
        )}
        confirmText={
          <>
            {isRevoking && <Loader2 className="me-2 h-4 w-4 animate-spin" />}
            {t('confirm.session.revoke', 'Sign out')}
          </>
        }
        destructive
        isLoading={isRevoking}
        handleConfirm={revokeOne}
      />
      <ConfirmDialog
        open={confirmAll}
        onOpenChange={setConfirmAll}
        title={t('confirm.session.revokeOthersTitle', 'Sign out all other sessions?')}
        desc={t(
          'confirm.session.revokeOthersDesc',
          'Every device except this one is signed out at once and has to sign in again.'
        )}
        confirmText={
          <>
            {isRevokingAll && <Loader2 className="me-2 h-4 w-4 animate-spin" />}
            {t('confirm.session.revokeOthers', 'Sign out all others')}
          </>
        }
        destructive
        isLoading={isRevokingAll}
        handleConfirm={revokeOthers}
      >
        <RevokeApiKeysOption
          id="signout-revoke-keys"
          checked={revokeKeys}
          onCheckedChange={setRevokeKeys}
          count={activeApiKeys}
        />
      </ConfirmDialog>
    </SettingsSection>
  )
}
