-- Intentional no-op. The up migration only re-applies schema that earlier
-- migrations (002571, 002817, 002830) own; dropping it here would destroy
-- the data of those migrations. Their own down files remove the objects.
SELECT 1;
