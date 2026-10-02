-- Cannot reliably reverse — subdomains may have been correctly typed before.
-- This migration only fixes mistyped assets, so rollback is a no-op.
-- If needed, manually UPDATE specific assets back to 'domain'.
SELECT 1;
