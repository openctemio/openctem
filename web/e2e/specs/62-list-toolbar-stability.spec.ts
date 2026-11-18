/**
 * The list header stability gate on Findings, Assets and Scans (the rules and
 * their steps: e2e/helpers/list-toolbar-stability.ts). The other lists are in
 * 35-list-toolbar-stability-other-lists, so the two halves run in different
 * CI shards.
 */
import { test } from '../fixtures/authenticated-page'
import {
  benchmarksNeverMoveTheHeader,
  changedViewSaysSo,
  headerHoldsStill,
  oneOverflowMenu,
  pagingHoldsStill,
  quickViewPinNeverCoversTheCount,
  saysItsCountOnce,
} from '../helpers/list-toolbar-stability'

test.describe('Findings list header', { tag: ['@findings'] }, () => {
  headerHoldsStill('/findings')
  pagingHoldsStill('/findings')
  saysItsCountOnce('/findings')
  changedViewSaysSo()
  quickViewPinNeverCoversTheCount()
  oneOverflowMenu()
  benchmarksNeverMoveTheHeader()
})
test.describe('Assets list header', { tag: ['@assets'] }, () => {
  headerHoldsStill('/assets')
  pagingHoldsStill('/assets')
  saysItsCountOnce('/assets')
})
test.describe('Scans list header', { tag: ['@scans'] }, () => {
  headerHoldsStill('/scans')
  pagingHoldsStill('/scans')
  saysItsCountOnce('/scans')
})
