'use client'

import { useEffect, useState } from 'react'
import Link from 'next/link'
import { ArrowUpCircle, ShieldAlert, X } from 'lucide-react'
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import { Button } from '@/components/ui/button'
import { useTranslation } from '@/context/i18n-provider'
import { useVersionCheck } from '../api/use-version-check'

/** Where the software updates page lives. */
export const SOFTWARE_UPDATES_URL = '/admin/system/software-updates'

const DISMISS_KEY = 'openctem.admin.update-dismissed'

function readDismissed(): string | null {
  try {
    return window.localStorage.getItem(DISMISS_KEY)
  } catch {
    return null
  }
}

function writeDismissed(version: string) {
  try {
    window.localStorage.setItem(DISMISS_KEY, version)
  } catch {
    // Storage unavailable (private window, blocked site data): the banner
    // simply shows again on the next page.
  }
}

/**
 * The console-wide notice from the version check (RFC-105): a security
 * release that fixes an advisory affecting the running version (always
 * shown), or a newer release (dismissible per version). Nothing when the
 * check has no information or the instance is up to date.
 */
export function VersionCheckBanner() {
  const { t } = useTranslation()
  const { data } = useVersionCheck()
  const [dismissed, setDismissed] = useState<string | null>(null)

  useEffect(() => {
    setDismissed(readDismissed())
  }, [])

  if (!data?.comparable) return null

  if (data.advisories.length > 0) {
    const severity = data.severity ?? 'high'
    return (
      <div className="px-4 pt-2">
        <Alert variant="destructive" data-testid="version-check-security">
          <ShieldAlert />
          <AlertTitle>
            {t(
              'admin.versionCheck.banner.securityTitle',
              'Security release: upgrade to {version}',
              {
                version: data.fixed_in ?? data.latest ?? '',
              }
            )}
          </AlertTitle>
          <AlertDescription>
            <p>
              {t(
                'admin.versionCheck.banner.securityBody',
                'The running version {running} is affected by {count} published security advisories (highest severity: {severity}).',
                {
                  running: data.running,
                  count: data.advisories.length,
                  severity: t(`severity.${severity}`, severity),
                }
              )}
            </p>
            <Link href={SOFTWARE_UPDATES_URL} className="font-medium underline underline-offset-4">
              {t('admin.versionCheck.banner.details', 'See the advisories')}
            </Link>
          </AlertDescription>
        </Alert>
      </div>
    )
  }

  if (!data.update_available || !data.latest || dismissed === data.latest) return null
  const latest = data.latest
  return (
    <div className="px-4 pt-2">
      <Alert data-testid="version-check-update">
        <ArrowUpCircle />
        <AlertTitle className="pe-8">
          {t('admin.versionCheck.banner.updateTitle', 'OpenCTEM {version} is available', {
            version: latest,
          })}
        </AlertTitle>
        <AlertDescription>
          <p>
            {t('admin.versionCheck.banner.updateBody', 'This instance runs {running}.', {
              running: data.running,
            })}{' '}
            <Link href={SOFTWARE_UPDATES_URL} className="font-medium underline underline-offset-4">
              {t('admin.versionCheck.banner.updateLink', 'What is new')}
            </Link>
          </p>
        </AlertDescription>
        <Button
          variant="ghost"
          size="icon"
          className="absolute end-2 top-2 size-7"
          aria-label={t('admin.versionCheck.banner.dismiss', 'Hide until the next release')}
          onClick={() => {
            writeDismissed(latest)
            setDismissed(latest)
          }}
        >
          <X className="size-4" />
        </Button>
      </Alert>
    </div>
  )
}
