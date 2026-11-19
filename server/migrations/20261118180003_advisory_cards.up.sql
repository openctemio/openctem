-- Advisory cards (docs/rfcs/RFC-117-emerging-threat-alerts.md, "Advisory
-- cards"): reviewed, product-level statements from the signed vulnerability
-- bundle (the cards stream). Public facts only, platform-wide, written only by
-- the bundle importer; no tenant data. Every revision is kept.

CREATE TABLE advisory_cards (
    card_id         TEXT PRIMARY KEY CHECK (card_id ~ '^OCA-[0-9]{4}-[0-9]{4,6}$'),
    revision        INTEGER NOT NULL CHECK (revision >= 1),
    title           TEXT NOT NULL CHECK (length(title) BETWEEN 1 AND 160),
    severity        TEXT NOT NULL CHECK (severity IN ('critical', 'high', 'medium', 'low')),
    exploitation    TEXT NOT NULL CHECK (exploitation IN ('none', 'poc_public', 'weaponised', 'exploited_itw', 'vendor_confirmed_exploited')),
    review_state    TEXT NOT NULL CHECK (review_state IN ('reported', 'reviewed', 'withdrawn')),
    -- NULL for a reported card (no person's review yet).
    review_mode     TEXT CHECK (review_mode IN ('two_person', 'single_review')),
    body            JSONB NOT NULL CHECK (length(body::text) <= 131072),
    published_at    TIMESTAMPTZ NOT NULL,
    updated_at      TIMESTAMPTZ NOT NULL,
    reviewed_at     TIMESTAMPTZ,
    feed_sequence   BIGINT,
    first_seen_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    imported_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);
COMMENT ON TABLE advisory_cards IS
    'Current revision of each advisory card from the signed vulnerability bundle (RFC-117). Public facts, platform-wide; body is the validated card.';

-- A same-revision withdrawal is kept under its own key, so both bodies stay.
CREATE TABLE advisory_card_revisions (
    card_id      TEXT NOT NULL REFERENCES advisory_cards(card_id) ON DELETE CASCADE,
    revision     INTEGER NOT NULL CHECK (revision >= 1),
    review_state TEXT NOT NULL CHECK (review_state IN ('reported', 'reviewed', 'withdrawn')),
    body         JSONB NOT NULL CHECK (length(body::text) <= 131072),
    imported_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (card_id, revision, review_state)
);
COMMENT ON TABLE advisory_card_revisions IS
    'Every revision of an advisory card the platform imported (kept for as long as the card exists; never overwritten).';

-- The last cards stream applied (one row): the stream is applied whenever
-- its file differs; the data date is kept for the freshness status only.
CREATE TABLE advisory_card_stream (
    singleton     BOOLEAN PRIMARY KEY DEFAULT true CHECK (singleton),
    file_sha256   TEXT NOT NULL CHECK (file_sha256 ~ '^[0-9a-f]{64}$'),
    feed_sequence BIGINT,
    as_of         TIMESTAMPTZ NOT NULL,
    applied_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- The vulnerability ids a card groups: their events open the card's alert.
CREATE TABLE advisory_card_vulns (
    card_id TEXT NOT NULL REFERENCES advisory_cards(card_id) ON DELETE CASCADE,
    vuln_id TEXT NOT NULL CHECK (length(vuln_id) BETWEEN 1 AND 64),
    PRIMARY KEY (card_id, vuln_id)
);
CREATE INDEX idx_advisory_card_vulns_vuln ON advisory_card_vulns (vuln_id);

-- The products a card names, by catalog key; joined to software_products at
-- read time so a product created later still matches.
CREATE TABLE advisory_card_products (
    card_id     TEXT NOT NULL REFERENCES advisory_cards(card_id) ON DELETE CASCADE,
    part        CHAR(1) NOT NULL CHECK (part IN ('a', 'o', 'h')),
    cpe_vendor  TEXT NOT NULL CHECK (length(cpe_vendor) BETWEEN 1 AND 128),
    cpe_product TEXT NOT NULL CHECK (length(cpe_product) BETWEEN 1 AND 128),
    PRIMARY KEY (card_id, part, cpe_vendor, cpe_product)
);
CREATE INDEX idx_advisory_card_products_key ON advisory_card_products (part, cpe_vendor, cpe_product);

-- Card events in the vulnerability event log (vuln_id is the card id).
ALTER TABLE vuln_events DROP CONSTRAINT IF EXISTS vuln_events_kind_check;
ALTER TABLE vuln_events ADD CONSTRAINT vuln_events_kind_check CHECK (kind IN ('published', 'ranges_added', 'ranges_widened',
    'severity_up', 'kev_added', 'epss_crossed', 'rejected', 'card_published', 'card_updated', 'card_withdrawn')) NOT VALID;
-- VALIDATE runs in its own migration (advisory_cards_validate): here it
-- would scan vuln_events under the ACCESS EXCLUSIVE lock of the ALTER above.

-- The card a vulnerability's alert was grouped into (resolved with reason
-- grouped_into_card). The person's note and the actor stay untouched.
ALTER TABLE threat_alerts ADD COLUMN grouped_into_card TEXT;
CREATE INDEX idx_threat_alerts_grouped_into_card ON threat_alerts (grouped_into_card) WHERE grouped_into_card IS NOT NULL;
