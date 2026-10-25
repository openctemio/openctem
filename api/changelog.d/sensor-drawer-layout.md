### Fixed: the sensor drawer no longer draws a long SDK version over the next field

- The Version field shows the sensor release and its update status; the SDK moves to More details, where a pseudo-version (a build of an unreleased commit) reads "v0.37.1 pre-release" with the full string under it. A long value stays inside its column everywhere the version cell is used.
- The drawer header's subline lists its parts without a separator glyph and wraps on a phone instead of cutting off the address. The same holds for every drawer header, the activity summary card, the setup check counts and the job list.
- "Unhardened" in the header is a button: its tooltip names each gap and it scrolls to the security posture section, which now links to the sensor hardening guide.
- The grant's remote actions read in words ("Pause and drain: always allowed", "Also allowed: key rotation") instead of protocol identifiers. Tier names read "T1: active, non-intrusive".
- The API key field shows when the key was last used and, for administrators, a Rotate key button; a sensor without a key prefix no longer shows a bare ellipsis. Key material is never shown.
- The network path section keeps its explanation behind "How network paths work".
- Drawer tabs: each tab's `aria-controls` names the drawer body, and the "More" menu button sits beside the tab list instead of inside it.
- Label and value lists in the sensor drawer use the shared components; a test now refuses new hand-written `<dt>` lists outside the shared components, and the drawer end-to-end spec fails when two pieces of text are drawn over each other.
