### Fixed: platform notices no longer push the page down when it loads

- Within a session a page renders before the session data that carries the platform notices and the support-access banner, so a banner used to appear a moment later and move the whole page (layout shift 0.12 to 0.16 on every page on a phone). The banner area now keeps the height its banners had on the previous page while that data loads. Only the height is kept (session storage, per organization), never the banner text.
