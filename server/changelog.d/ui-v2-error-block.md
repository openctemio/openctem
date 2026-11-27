### Changed: a page or list that fails to load says "Couldn't load" and keeps one alignment

- The shared error block reads "Couldn't load {what}" instead of "Failed to load {what}", and a server failure says "The server did not answer. Nothing was changed." with Retry and Report the problem (Vietnamese: "Máy chủ không phản hồi. Không có gì bị thay đổi.").
- Inside a list's frame the block was centred while its icon and buttons stayed at the start; it is start-aligned now, like every alert (every list).
- Docs: web/docs/ui-style-contract.md (error block)
