### Fixed: scan buttons match what the API allows

- Quick scan now needs `scans:write` and `scans:execute` in the console, as the API does; it showed for `scans:write` alone and always failed.
- The workflow editor and the workflows list no longer offer Save draft, Publish, Discard draft, step changes, the enable switch, Edit, Clone or Use template to members without `scan_workflows:write`; the editor opens read-only for them.
