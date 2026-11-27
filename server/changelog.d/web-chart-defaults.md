### Changed: one set of chart defaults

- Axis labels, guide lines, hover cursors, marker lines and the tooltip box of
  every chart come from one module (`web/src/components/charts/chart-defaults.ts`),
  all from theme tokens, so charts read the same in light and dark. The
  dashboard trend charts and the program health chart use it; nothing looks
  different.
- Docs: web/docs/ui-style-contract.md ("Charts").
