### Fixed: the sidebar drawer on a phone holds still and shows one current row

- The phone drawer scrolls as one column (header, nav and footer together), so the footer no longer squeezes the nav to a sliver on a short or sideways screen and iOS Safari has no nested scroller to bounce.
- Sheets and dialogs move above the keyboard only while a text field is focused; browser toolbar changes, the end-of-scroll bounce and pinch zoom no longer move the panel's bottom edge every frame.
- Sheets lost a 500 ms transition on every property that ran on top of their slide animation.
- One filled row in the sidebar: a row whose quick view is current (Findings with Active) keeps its weight without the fill, and a pinned page or quick view mirrors the current row unfilled.
- The pin button is not offered in the phone drawer, where it sat over every row's count.
- The drawer no longer scrolls sideways: a few pixels of horizontal overflow let a finger drag the rows left and clip the first letters of every label.
