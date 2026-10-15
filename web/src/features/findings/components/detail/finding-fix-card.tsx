'use client'

/**
 * The Fix card: the one concrete action that closes the finding, by type
 * (lib/fix-guidance.ts). "Upgrade cross-spawn 7.0.3 → 7.0.5" with the npm
 * command, "Revoke and rotate the Stripe key", "Set encryption to AES256"…
 * Nothing renders when the finding has no concrete fix.
 */

import {
  ArrowRight,
  Check,
  ChevronRight,
  Copy,
  ExternalLink,
  Layers,
  TriangleAlert,
  Wrench,
} from 'lucide-react'
import { useState } from 'react'
import Link from '@/components/link'
import { useTranslation } from '@/context/i18n-provider'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { copyToClipboard } from '@/lib/clipboard'
import { cn } from '@/lib/utils'
import { SafeExternalLink } from '@/components/safe-external-link'
import { SeverityBadge } from '@/features/shared/components/severity-badge'
import type { Severity } from '@/features/shared/types'
import type { FindingDetail, FindingFixPlan, FindingFixPlanItem } from '../../types'
import { fixGuidance, type FixCommand } from '../../lib/fix-guidance'
import { buildRepositoryCodeUrl } from '../../lib/repository-url'

function CodeBlock({ cmd }: { cmd: FixCommand }) {
  const { t } = useTranslation()
  const [copied, setCopied] = useState(false)
  return (
    <div className="min-w-0">
      <div className="mb-1 text-xs text-muted-foreground">{cmd.label}</div>
      <div className="relative">
        <pre className="overflow-x-auto rounded-md border bg-muted/60 py-2 ps-3 pe-10 font-mono text-xs leading-relaxed">
          {cmd.code}
        </pre>
        <Button
          type="button"
          variant="ghost"
          size="icon"
          className="absolute end-1 top-1 size-7"
          aria-label={t('findings.fixCard.copySnippet', 'Copy {label} snippet', {
            label: cmd.label,
          })}
          onClick={async () => {
            if (await copyToClipboard(cmd.code)) {
              setCopied(true)
              setTimeout(() => setCopied(false), 1500)
            }
          }}
        >
          {copied ? <Check className="h-3.5 w-3.5" /> : <Copy className="h-3.5 w-3.5" />}
        </Button>
      </div>
      {cmd.note && <p className="mt-1 text-xs text-muted-foreground">{cmd.note}</p>}
    </div>
  )
}

function Version({ children, tone }: { children: React.ReactNode; tone?: 'from' | 'to' }) {
  return (
    <code
      className={cn(
        'rounded px-1.5 py-0.5 font-mono text-sm',
        tone === 'to' ? 'bg-success/15 text-success' : 'bg-muted'
      )}
    >
      {children}
    </code>
  )
}

function PlanItems({ items }: { items: FindingFixPlanItem[] }) {
  return (
    <ul className="mt-1.5 space-y-1">
      {items.map((i) => (
        <li key={i.id} className="flex min-w-0 items-center gap-2 text-sm">
          <SeverityBadge severity={i.severity as Severity} className="shrink-0" />
          <Link
            href={`/findings/${encodeURIComponent(i.id)}`}
            className="min-w-0 truncate underline-offset-2 hover:underline"
          >
            {i.cveId ? <span className="font-mono text-xs">{i.cveId}</span> : null}
            {i.cveId ? ' · ' : null}
            {i.title}
          </Link>
        </li>
      ))}
    </ul>
  )
}

/**
 * "Upgrading Django to 4.2.30 fixes 3 of 4 open findings for this package
 * here": the package plan from GET /findings/{id} (package_fix). Shown only
 * when the package has more than one open finding on the asset.
 */
export function PackageFixPlan({
  plan,
  packageName,
}: {
  plan: FindingFixPlan
  packageName: string
}) {
  const { t } = useTranslation()
  if (!plan.targetVersion || plan.openFindings < 2 || plan.resolvesCount === 0) return null
  const all = plan.resolvesCount === plan.openFindings && !plan.truncated
  return (
    <div data-slot="package-fix-plan" className="mt-3 border-t pt-3">
      <p className="flex items-start gap-1.5 text-sm">
        <Layers className="mt-0.5 h-4 w-4 shrink-0 text-muted-foreground" aria-hidden />
        <span>
          {all
            ? t(
                'findings.fixCard.planResolvesAll',
                'Upgrading {package} to {version} fixes all {count} open findings of this package on this asset.',
                { package: packageName, version: plan.targetVersion, count: plan.openFindings }
              )
            : t(
                'findings.fixCard.planResolvesSome',
                'Upgrading {package} to {version} fixes {resolved} of {count} open findings of this package on this asset.',
                {
                  package: packageName,
                  version: plan.targetVersion,
                  resolved: plan.resolvesCount,
                  count: plan.truncated ? `${plan.openFindings}+` : plan.openFindings,
                }
              )}
          {plan.majorUpgrade && (
            <Badge variant="outline" className="ms-1.5 border-warning/50 text-warning">
              {t('findings.fixCard.majorUpgrade', 'Major upgrade')}
            </Badge>
          )}
        </span>
      </p>
      {plan.completeVersion && (
        <p className="mt-1 ps-5.5 text-sm text-muted-foreground">
          {t(
            'findings.fixCard.planComplete',
            'Upgrading to {version} fixes {count} of them, every one with a known fix.',
            { version: plan.completeVersion, count: plan.completeResolves ?? 0 }
          )}
          {plan.completeMajor && (
            <Badge variant="outline" className="ms-1.5 border-warning/50 text-warning">
              {t('findings.fixCard.majorUpgrade', 'Major upgrade')}
            </Badge>
          )}
        </p>
      )}
      <details className="group mt-1 ps-5.5">
        <summary className="inline-flex cursor-pointer list-none items-center gap-1 rounded-sm text-xs text-muted-foreground select-none hover:text-foreground focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none [&::-webkit-details-marker]:hidden">
          <ChevronRight className="h-3 w-3 transition-transform group-open:rotate-90" aria-hidden />
          {t('findings.fixCard.planShow', 'Show the findings')}
        </summary>
        <PlanItems items={plan.resolves} />
        {plan.remaining.length > 0 && (
          <>
            <p className="mt-2 text-xs font-medium text-muted-foreground">
              {t('findings.fixCard.planRemaining', 'Still open after this upgrade')}
            </p>
            <PlanItems items={plan.remaining} />
          </>
        )}
      </details>
    </div>
  )
}

/** Longest chain shown in full; longer ones keep both ends. */
const CHAIN_SHOWN = 4

/** "Transitive via express → body-parser"; the full chain in the tooltip. */
function DependencyChain({ via }: { via: string[] }) {
  const { t } = useTranslation()
  const shown = via.length > CHAIN_SHOWN ? [via[0], '…', ...via.slice(-(CHAIN_SHOWN - 2))] : via
  return (
    <span className="min-w-0 break-words" title={via.join(' → ')}>
      {t('findings.fixCard.transitiveVia', 'Transitive via {path}', {
        path: shown.join(' → '),
      })}
    </span>
  )
}

/** The lock file and the package's line, linked to the repository when known. */
function ManifestRef({
  file,
  line,
  codeUrl,
}: {
  file: string
  line?: number
  codeUrl: string | null
}) {
  const { t } = useTranslation()
  const label = line ? `${file}:${line}` : file
  return (
    <span className="min-w-0 break-all">
      <span className="whitespace-pre">{`${t('findings.fixCard.inPrefix', 'in')} `}</span>
      {codeUrl ? (
        <SafeExternalLink
          href={codeUrl}
          className="inline-flex items-center gap-0.5 font-mono text-xs underline-offset-2 hover:underline"
          title={t('findings.fixCard.openLockfile', 'Open the lock file at this line')}
        >
          {label}
          <ExternalLink className="h-3 w-3" aria-hidden />
        </SafeExternalLink>
      ) : (
        <span className="font-mono text-xs">{label}</span>
      )}
    </span>
  )
}

export interface FindingFixCardProps {
  finding: FindingDetail
  /** Opens the full remediation plan (the Remediation tab). */
  onOpenPlan?: () => void
  /** Drawer: no commands, just the action line. */
  compact?: boolean
  className?: string
}

export function FindingFixCard({ finding, onOpenPlan, compact, className }: FindingFixCardProps) {
  const { t } = useTranslation()
  const g = fixGuidance(finding)
  if (!g) return null

  let body: React.ReactNode
  switch (g.kind) {
    case 'upgrade': {
      const how: React.ReactNode[] = []
      if (g.dependencyType === 'direct') {
        how.push(t('findings.fixCard.directDep', 'Direct dependency'))
      } else if (g.dependencyType === 'transitive') {
        how.push(
          g.via ? (
            <DependencyChain key="via" via={g.via} />
          ) : (
            t('findings.fixCard.transitiveDep', 'Transitive dependency')
          )
        )
      }
      if (g.manifestFile) {
        how.push(
          <ManifestRef
            key="file"
            file={g.manifestFile}
            line={g.manifestLine}
            codeUrl={buildRepositoryCodeUrl({
              repositoryUrl: finding.repositoryUrl,
              filePath: g.manifestFile,
              startLine: g.manifestLine,
              commitSha: finding.commitSha,
              branch: finding.branch,
            })}
          />
        )
      }
      if (g.ecosystem) how.push(g.ecosystem)
      body = (
        <>
          <p className="flex flex-wrap items-center gap-x-1.5 gap-y-1 text-base font-medium">
            {t('findings.fixCard.upgrade', 'Upgrade')}{' '}
            <span className="font-semibold">{g.packageName}</span>
            <Version tone="from">{g.from}</Version>
            <ArrowRight
              className="h-4 w-4 text-muted-foreground"
              aria-label={t('findings.fixCard.to', 'to')}
            />
            <Version tone="to">{g.to}</Version>
            {g.majorUpgrade && (
              <Badge
                variant="outline"
                className="gap-1 border-warning/50 text-warning"
                title={t(
                  'findings.fixCard.majorUpgradeHint',
                  'Crosses a major version: check the release notes for breaking changes.'
                )}
              >
                <TriangleAlert className="h-3 w-3" aria-hidden />
                {t('findings.fixCard.majorUpgrade', 'Major upgrade')}
              </Badge>
            )}
          </p>
          {how.length > 0 && (
            <p className="mt-1 flex flex-wrap items-center gap-y-0.5 text-sm text-muted-foreground">
              {how.map((h, i) => (
                <span key={i} className="inline-flex min-w-0 items-center">
                  {i > 0 && (
                    <span aria-hidden className="whitespace-pre">
                      {' · '}
                    </span>
                  )}
                  {h}
                </span>
              ))}
            </p>
          )}
          {!compact && g.commands.length > 0 && (
            <div className="mt-3 grid gap-2">
              {g.commands.map((c) => (
                <CodeBlock key={c.label} cmd={c} />
              ))}
            </div>
          )}
          {g.otherFixedVersions.length > 0 && (
            <p className="mt-2 text-xs text-muted-foreground">
              {t('findings.fixCard.alsoFixedIn', 'Also fixed in')}{' '}
              {g.otherFixedVersions.map((v, i) => (
                <span key={v}>
                  {i > 0 && ', '}
                  <code className="font-mono">{v}</code>
                </span>
              ))}{' '}
              {t('findings.fixCard.otherLines', '(other release lines).')}
            </p>
          )}
          {finding.packageFix && (
            <PackageFixPlan plan={finding.packageFix} packageName={g.packageName} />
          )}
        </>
      )
      break
    }
    case 'no-fix':
      body = (
        <>
          <p className="text-base font-medium">
            {t('findings.fixCard.noFixTitle', 'No fixed version of {package} yet', {
              package: g.packageName,
            })}
          </p>
          <p className="mt-1 text-sm text-muted-foreground">
            {t(
              'findings.fixCard.noFixBody',
              '{from} is affected and the advisory lists no patched release. Replace the package, remove the vulnerable code path, or accept the risk with a compensating control.',
              { from: g.from }
            )}
          </p>
        </>
      )
      break
    case 'rotate-secret':
      body = (
        <>
          <p className="text-base font-medium">
            {g.service
              ? t('findings.fixCard.rotateService', 'Revoke and rotate the {service} credential', {
                  service: g.service,
                })
              : t('findings.fixCard.rotateGeneric', 'Revoke and rotate the credential')}
          </p>
          {!compact && (
            <ol className="mt-2 list-decimal space-y-1 ps-5 text-sm text-muted-foreground">
              {g.steps.map((s) => (
                <li key={s}>{s}</li>
              ))}
            </ol>
          )}
        </>
      )
      break
    case 'misconfig':
      body = (
        <>
          <p className="text-base font-medium">
            {g.resource ? (
              <>
                {t('findings.fixCard.reconfigure', 'Reconfigure')}{' '}
                <span className="font-mono text-sm">{g.resource}</span>
              </>
            ) : (
              t('findings.fixCard.reconfigureResource', 'Reconfigure the resource')
            )}
          </p>
          {g.policy && (
            <p className="mt-1 text-sm text-muted-foreground">
              {t('findings.fixCard.policy', 'Policy: {policy}', { policy: g.policy })}
            </p>
          )}
          {!compact && (g.expected || g.actual) && (
            <dl className="mt-3 grid gap-2 sm:grid-cols-2">
              <div className="min-w-0 rounded-md border border-success/30 bg-success/5 p-2.5">
                <dt className="text-xs font-medium text-success">
                  {t('findings.fixCard.expected', 'Expected')}
                </dt>
                <dd className="mt-1 font-mono text-xs break-words whitespace-pre-wrap">
                  {g.expected || t('findings.fixCard.notConfigured', 'Not configured')}
                </dd>
              </div>
              <div className="min-w-0 rounded-md border border-destructive/30 bg-destructive/5 p-2.5">
                <dt className="text-xs font-medium text-destructive">
                  {t('findings.fixCard.actual', 'Actual')}
                </dt>
                <dd className="mt-1 font-mono text-xs break-words whitespace-pre-wrap">
                  {g.actual || t('findings.fixCard.notConfigured', 'Not configured')}
                </dd>
              </div>
            </dl>
          )}
        </>
      )
      break
    case 'text':
      body = (
        <>
          {g.text && (
            <p
              className={cn(
                'text-sm leading-relaxed whitespace-pre-wrap',
                compact && 'line-clamp-3'
              )}
            >
              {g.text}
            </p>
          )}
          {!compact && g.fixCode && (
            <div className="mt-3">
              <CodeBlock
                cmd={{
                  label: t('findings.fixCard.suggestedFix', 'Suggested fix'),
                  code: g.fixCode,
                }}
              />
            </div>
          )}
        </>
      )
      break
  }

  return (
    <section
      aria-label={t('findings.fixCard.fix', 'Fix')}
      data-slot="finding-fix"
      data-kind={g.kind}
      className={cn('rounded-lg border bg-card p-4', className)}
    >
      <div className="mb-2 flex items-center justify-between gap-2">
        <h2 className="flex items-center gap-1.5 text-sm font-semibold">
          <Wrench className="h-4 w-4" aria-hidden />
          {t('findings.fixCard.fix', 'Fix')}
        </h2>
        {onOpenPlan && (
          <Button variant="link" size="sm" className="h-auto p-0 text-xs" onClick={onOpenPlan}>
            {t('findings.fixCard.remediationPlan', 'Remediation plan')}
          </Button>
        )}
      </div>
      {body}
    </section>
  )
}
