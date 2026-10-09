### Security: Jira comments carry finding titles as text, not wiki markup

- Comments that OpenCTEM adds to a linked Jira issue (a retest or a scan found the finding fixed, or saw it again) included the finding title and the retest reason as they were. Both can come from a sensor or a scan target. A title such as `[Re-authenticate|https://evil.example/login] !https://evil.example/px.png! [~admin]` rendered in Jira as a link, an image beacon and a mention. Comments are now encoded like issue descriptions: every wiki markup character is escaped and URLs are defanged.
