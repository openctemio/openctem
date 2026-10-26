'use client'

import { ArrowUpCircle } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Card, CardAction, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table'
import { useTranslation } from '@/context/i18n-provider'
import type { CveExposure, CveExposureUpgrade } from '../../types/exposure'
import { share } from '../../lib/vuln-page'

/**
 * "Why": the installed package versions the active findings name, the fix
 * each needs, and the upgrade path per product ("upgrade X to 2.4.7: fixes
 * N findings on M assets"), with one remediation task for it.
 */
export function WhyCard({
  exposure,
  onCreateTask,
}: {
  exposure: CveExposure
  /** Opens a task for this upgrade; undefined when the caller may not create one. */
  onCreateTask?: (upgrade: CveExposureUpgrade) => void
}) {
  const { t } = useTranslation()
  const { components, upgrades } = exposure
  return (
    <Card data-slot="why-card" className="min-w-0">
      <CardHeader className="pb-3">
        <CardTitle className="text-base">
          {t('vulnPage.why.title', 'Why: affected software')}
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        {components.length === 0 ? (
          <p className="text-sm text-muted-foreground">
            {t(
              'vulnPage.why.none',
              'The findings name no installed package. The scanners that reported them check the service or host, not a package version.'
            )}
          </p>
        ) : (
          <div className="-mx-6 overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="ps-6">{t('vulnPage.why.col.package', 'Package')}</TableHead>
                  <TableHead>{t('vulnPage.why.col.version', 'Version')}</TableHead>
                  <TableHead>{t('vulnPage.why.col.fixed', 'Fixed in')}</TableHead>
                  <TableHead className="pe-6 text-end">
                    {t('vulnPage.why.col.assets', 'Assets')}
                  </TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {components.map((c) => (
                  <TableRow key={`${c.product_id}:${c.version}`}>
                    <TableCell className="max-w-[14rem] ps-6">
                      <span className="block truncate font-mono text-xs" title={c.purl || c.name}>
                        {c.purl ? c.purl.replace(/@[^@]*$/, '') : c.name}
                      </span>
                    </TableCell>
                    <TableCell className="font-mono text-xs">
                      {c.version || t('vulnPage.why.unknownVersion', 'unknown')}
                    </TableCell>
                    <TableCell className="font-mono text-xs text-success">
                      {c.recommended_fix || (
                        <span className="font-sans text-muted-foreground">
                          {t('vulnPage.why.noFix', 'No fix known')}
                        </span>
                      )}
                    </TableCell>
                    <TableCell className="pe-6 text-end tabular-nums">
                      {c.assets.toLocaleString()}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        )}
        {upgrades.length > 0 && (
          <ul className="space-y-2" aria-label={t('vulnPage.why.upgrades', 'Upgrade path')}>
            {upgrades.map((u) => (
              <li
                key={u.product_id}
                data-slot="upgrade"
                className="flex flex-wrap items-center justify-between gap-2 rounded-md border px-3 py-2"
              >
                <span className="flex min-w-0 items-start gap-2 text-sm">
                  <ArrowUpCircle
                    className="mt-0.5 h-4 w-4 shrink-0 text-muted-foreground"
                    aria-hidden
                  />
                  <span className="min-w-0">
                    <span className="font-medium">
                      {t('vulnPage.why.upgradeTo', 'Upgrade {name} to {version}', {
                        name: u.name,
                        version: u.target,
                      })}
                    </span>
                    <span className="block text-xs text-muted-foreground">
                      {t(
                        'vulnPage.why.upgradeFixes',
                        'Fixes {findings, plural, one {# finding} other {# findings}} on {assets, plural, one {# asset} other {# assets}}',
                        { findings: u.fixes_findings, assets: u.on_assets }
                      )}
                      {u.major_change && (
                        <> {t('vulnPage.why.major', '(a major version change)')}</>
                      )}
                      {u.no_fix_findings > 0 && (
                        <>
                          {' '}
                          {t('vulnPage.why.noFixCount', '{count} more have no known fix', {
                            count: u.no_fix_findings,
                          })}
                        </>
                      )}
                    </span>
                  </span>
                </span>
                {onCreateTask && (
                  <Button size="sm" variant="outline" onClick={() => onCreateTask(u)}>
                    {t('vulnPage.why.createTask', 'Create task')}
                  </Button>
                )}
              </li>
            ))}
          </ul>
        )}
      </CardContent>
    </Card>
  )
}

/** "Who found it": per tool, the impacted assets it reported, and single-source assets. */
export function WhoCard({ exposure }: { exposure: CveExposure }) {
  const { t } = useTranslation()
  const { sources, assets, single_source_assets: single } = exposure
  const base = Math.max(assets.impacted, 1)
  return (
    <Card data-slot="who-card" className="min-w-0">
      <CardHeader className="pb-3">
        <CardTitle className="text-base">{t('vulnPage.who.title', 'Who found it')}</CardTitle>
        <CardAction className="self-center">
          <span className="text-xs text-muted-foreground">
            {t('vulnPage.who.hint', 'Source coverage')}
          </span>
        </CardAction>
      </CardHeader>
      <CardContent className="space-y-2 text-sm">
        {sources.length === 0 ? (
          <p className="text-muted-foreground">
            {t('vulnPage.who.none', 'No open finding, so no source to show.')}
          </p>
        ) : (
          <ul className="space-y-2">
            {sources.map((s) => {
              const pct = share(s.assets, base)
              return (
                <li key={`${s.source}:${s.name}`} className="flex items-center gap-3">
                  <span
                    className="h-1.5 w-16 shrink-0 overflow-hidden rounded-full bg-muted"
                    role="img"
                    aria-label={t('vulnPage.who.share', '{count} of {total} assets', {
                      count: s.assets,
                      total: assets.impacted,
                    })}
                  >
                    <span
                      className="block h-full bg-muted-foreground"
                      style={{ width: `${pct}%` }}
                    />
                  </span>
                  <span className="min-w-0 truncate">{s.name}</span>
                  <span className="ms-auto shrink-0 text-xs tabular-nums text-muted-foreground">
                    {t('vulnPage.who.ofAssets', '{count} of {total} assets', {
                      count: s.assets.toLocaleString(),
                      total: assets.impacted.toLocaleString(),
                    })}
                  </span>
                </li>
              )
            })}
          </ul>
        )}
        {single > 0 && (
          <p className="text-xs text-muted-foreground">
            {t(
              'vulnPage.who.single',
              '{count, plural, one {# asset was} other {# assets were}} found by one source only.',
              { count: single }
            )}
          </p>
        )}
      </CardContent>
    </Card>
  )
}
