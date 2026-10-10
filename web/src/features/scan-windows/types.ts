/**
 * Scan window policies (api docs/architecture/scan-windows.md, RFC-067):
 * when scans may touch which targets. Wire types come from the generated
 * OpenAPI types.
 */
import type { components } from '@/lib/api/generated/api.types'

type S = components['schemas']

export type ScanWindowPolicy = S['internal_infra_http_handler.ScanWindowPolicyResponse']
export type ScanWindowPolicyList = S['internal_infra_http_handler.ScanWindowPolicyListResponse']
export type ScanWindowPolicyRequest = S['internal_infra_http_handler.ScanWindowPolicyRequest']
export type ScanWindowSelector = S['internal_infra_http_handler.ScanWindowSelector']
export type ScanWindowSlot = S['internal_infra_http_handler.ScanWindowSlot']
export type ScanWindowOneOff = S['internal_infra_http_handler.ScanWindowOneOff']
export type ScanWindowPolicyPreview =
  S['github_com_openctemio_openctem_api_internal_app_scanwindow.Preview']

export type ScanWindowOverride = S['internal_infra_http_handler.ScanWindowOverrideResponse']
export type ScanWindowOverrideList = S['internal_infra_http_handler.ScanWindowOverrideListResponse']
export type ScanWindowOverrideRequest = S['internal_infra_http_handler.ScanWindowOverrideRequest']

export type ScanWindowEvaluateRequest = S['internal_infra_http_handler.ScanWindowEvaluateRequest']
export type ScanWindowEvaluateResponse = S['internal_infra_http_handler.ScanWindowEvaluateResponse']
/** What the windows mean now for one target or asset. */
export type WindowDecision =
  S['github_com_openctemio_openctem_api_internal_app_scanwindow.TargetDecision']

/** A window that keeps work from running now, and until when. */
export type WindowBlock = S['github_com_openctemio_openctem_api_pkg_domain_scanwindow.Block']
/** A window that applies to a target. */
export type WindowRef = S['github_com_openctemio_openctem_api_pkg_domain_scanwindow.Ref']
/** Why a queued task waits for a window (RunTask.window_hold). */
export type WindowHold = S['github_com_openctemio_openctem_api_pkg_domain_scanwindow.Hold']
/** A target that cannot be scanned now (previews and run waits). */
export type TargetWait = S['github_com_openctemio_openctem_api_internal_app_scan.TargetWait']
/** What the windows mean for a scan's targets (routing and workflow previews). */
export type WindowPreview = S['github_com_openctemio_openctem_api_internal_app_scan.WindowPreview']
/** The targets of a run that waited for their windows (ScanRun.window_waits). */
export type RunWindowWaits = S['internal_infra_http_handler.RunWindowWaitsResponse']

export type ScanWindowKind = 'allow' | 'blackout'
/** 0 every tool, 1 active and intrusive (default), 2 intrusive only. */
export type ScanWindowTier = 0 | 1 | 2
