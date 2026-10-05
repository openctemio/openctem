-- A validated constraint cannot be marked NOT VALID again, and does not need
-- to be: 000921 down drops the constraints themselves. Nothing to undo here.
SELECT 1;
