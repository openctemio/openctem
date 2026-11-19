### Fixed: detail pages and the console no longer cut buttons, stack step cards or show English on Vietnamese pages

- A scan workflow's step cards no longer sit on top of each other: once the cards are drawn, overlapping ones move down so each is readable.
- A row's labelled buttons (Cancel on a scan's runs, Block on the console's AI applications, Approve in queues, Check on domain proofs) are no longer cut at the table's edge.
- Opening a record that no longer exists says "Couldn't find ..." in the reader's language, without a Retry or the server's English message.
- A scan's page says "Manual" once and in Vietnamese on a Vietnamese page; its schedule type is translated.
- The severity breakdown on asset and pentest campaign pages is translated and wraps on a phone instead of cutting the labels.
- On a phone, a list's buttons at the end of the toolbar wrap instead of running off the start of the screen, and a card value of two parts (a trigger and who started it) keeps a space between them and ends in an ellipsis.

Docs: web/docs/ui-style-contract.md (column kinds: labelled buttons go in a `decisions` column)
