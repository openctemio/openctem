### Fixed: the finding drawer shows the HTTP response of web findings

- The drawer showed only the first evidence item, which for nuclei findings was the tool's curl command (stored after the HTTP exchange), so the request and response never appeared. It now shows the HTTP exchange of the newest detection in a compact layout (headers folded unless matched, the body scrolled to the matched part) with a link to all evidence.
- Everywhere evidence is shown (drawer, Evidence tab, triage mode), a tool's curl item is folded into the HTTP exchange of the same capture, which already offers Copy curl. Evidence kind names are translated.
