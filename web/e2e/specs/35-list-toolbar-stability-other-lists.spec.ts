/**
 * The list header stability gate on Vulnerabilities, Emerging threats, the
 * attack surface's Exposures, Technologies and Certificates, Sensors and Scan runs (the
 * rules and their steps: e2e/helpers/list-toolbar-stability.ts; Findings,
 * Assets and Scans: 62-list-toolbar-stability).
 */
import { test } from '../fixtures/authenticated-page'
import {
  headerHoldsStill,
  pagingHoldsStill,
  saysItsCountOnce,
} from '../helpers/list-toolbar-stability'

test.describe('Vulnerabilities list header', { tag: ['@vulnerabilities'] }, () => {
  headerHoldsStill('/vulnerabilities')
  pagingHoldsStill('/vulnerabilities')
  saysItsCountOnce('/vulnerabilities')
})
test.describe('Emerging threats list header', { tag: ['@prioritization'] }, () => {
  headerHoldsStill('/emerging-threats')
  pagingHoldsStill('/emerging-threats')
  saysItsCountOnce('/emerging-threats')
})
test.describe('Attack surface list headers', { tag: ['@attack-surface'] }, () => {
  for (const route of [
    '/attack-surface/exposures',
    '/attack-surface/technologies',
    '/attack-surface/certificates',
  ] as const) {
    headerHoldsStill(route)
    pagingHoldsStill(route)
    saysItsCountOnce(route)
  }
})
test.describe('Sensors list header', { tag: ['@sensors'] }, () => {
  headerHoldsStill('/sensors')
  saysItsCountOnce('/sensors')
})
test.describe('Scan runs list header', { tag: ['@scans'] }, () => {
  headerHoldsStill('/scans/runs')
  saysItsCountOnce('/scans/runs')
})
