### Fixed: the finding Evidence tab shows re-verify results and counts every source

- Re-verify and validation results and the compliance controls card are now shown on the Evidence tab even when the finding has no other evidence; "No evidence" appears only when every source is empty.
- The number on the Evidence tab counts tool evidence, re-verify and validation results, notes and uploaded files as well as code and attachments.
- Uploaded files of pentest and manual findings load through the API client; a failed load shows an error row with Retry instead of an empty section, and users without pentest finding read access no longer send the request.
- No API change.
