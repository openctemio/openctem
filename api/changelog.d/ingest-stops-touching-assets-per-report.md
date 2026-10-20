### Changed: a finished report no longer rewrites every asset it touched

- Report commit used to run a bulk `UPDATE assets SET updated_at = NOW()` over the touched assets "to refresh finding counts". Asset finding counts are computed when read, so nothing stored changed; the write only created a new row version (and index entries) per asset per report. It is removed. The asset upsert still stamps `updated_at` when an asset is seen.
