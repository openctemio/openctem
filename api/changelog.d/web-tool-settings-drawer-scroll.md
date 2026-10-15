### Fixed: an expanded tool in the sensor drawer's Tool settings is no longer cut off on a phone

- On a phone, opening a tool in a sensor's Tool settings scrolled the drawer frame itself: the expanded tool was cut off mid-card, a blank band appeared under it, and the rest could not be scrolled to. Opening a tool now scrolls only the drawer's body.
- Sheet, drawer and dialog frames clip their overflow instead of hiding it, so no script can scroll a frame out of place.
