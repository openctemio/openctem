### Fixed: the finding's data-flow tab shows the whole trace with its code

- The tab lists the steps of the trace in order from the source to the sink, sanitizer steps included (they were dropped), with each step's code (it was never shown: the console read a field the API does not send), file and line, function and class.
- Each step links to its file and line at the commit the trace was reported for, when the repository's web URL is known. The link never points at a branch or at the finding's latest commit, which could show other code.
- All text is translated (English, Vietnamese). A finding without a trace says "This scanner did not report a data flow".
