-- Nothing to undo. The up migration only switched off automations that use a
-- trigger or action the platform does not run. Switching them back on would
-- re-arm types the API refuses to activate, so the down leaves them off.
SELECT 1;
