### Added: POST /api/v1/query/parse checks a search box filter

- Takes search box text (short or long form), a filter document or a list's URL params on an entity and returns the version 1 filter document (relative times kept), its canonical short and long text, the top-level conditions as chips (or one "advanced" chip for groups chips cannot show, never flattened), the list's flat params when every chip has one, and problems with a code, a byte range and "did you mean" suggestions.
- Same permission as the entity's list (`findings:read` for findings); fields the caller may not use are unknown. Nothing reads data; rate limited per user (burst 30, 5 per second). A filter the findings list cannot run is reported as a `not_on_list` problem.
