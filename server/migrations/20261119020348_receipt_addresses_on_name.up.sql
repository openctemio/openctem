-- research/531 D1: an address inside a range a provider publishes for
-- infrastructure many organizations share, seen only as a name's DNS answer,
-- is recorded on the name (its ip_addresses set elements) instead of as an
-- address asset. The receipt counts those (name, address) pairs, so nothing
-- a report sent goes unaccounted. A constant default adds the column
-- without rewriting the table.
ALTER TABLE ingest_receipts
    ADD COLUMN addresses_on_name INTEGER NOT NULL DEFAULT 0;

COMMENT ON COLUMN ingest_receipts.addresses_on_name IS
    'research/531: DNS answers inside a shared provider range recorded on the name, not as address assets.';
