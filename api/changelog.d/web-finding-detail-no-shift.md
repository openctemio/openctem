### Fixed: the finding page no longer jumps while its panels load

- The finding page now appears once its bands and side panels (approval, remediation task, verification, retest, watchers) have answered, at most 1.5 seconds after the finding itself, instead of showing the body and then pushing it about 760px down on a phone (layout shift 0.29 to 0). The loading skeleton follows the page's own grid and order.
- New shared `SettleGroup` / `useSettleSignal` (`features/shared/components/settle-group.tsx`) for pages whose blocks load their own data.
