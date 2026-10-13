### Behaviour change: saved scans are never switched to live hosts first on their own

- Editing a scan with address ranges keeps its CIDR mode: an edit that names no mode keeps the stored one, so a scan saved before live hosts first existed keeps sweeping. Before, an edit switched it to live hosts first when its workflow had Host discovery.
- The edit form shows a saved scan without a mode as sweeping, with an inline "Live hosts first (recommended)" suggestion that switches with one click when the scan can run it.
- The scan detail page shows the same suggestion as a non-blocking hint for sweeping scans whose scanner or workflow can find live hosts first; switching needs scans write.
- The scan details describe a live hosts first scan as such (it was shown as "swept whole").
