### Fixed: a long non-ASCII asset description no longer loses the asset and its findings

- An asset description over 4 KB was cut at a byte offset, which could split a Vietnamese, CJK or emoji character. PostgreSQL refused the invalid UTF-8, so the asset was not stored and every finding on it was rejected. The description is now cut on a character boundary.
- The same byte cut was fixed in the other ingest values it applied to: the ingest job's stored error text, a trusted collector's source reference, the output-binding label and two log sanitizers. One shared helper, `safetext.TruncateBytes`, does the cut.
