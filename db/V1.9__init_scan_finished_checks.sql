-- This migration initializes the field 'checks_finished' of the current
-- running scans.
WITH running_scans AS (
    SELECT id, data FROM scans where data->>'status' = 'RUNNING' AND EXTRACT(MONTH from created_at) = 4
    AND EXTRACT(YEAR FROM created_at) = 2021 AND data->>'check_count' IS NOT NULL AND
    data->>'checks_finished' IS NULL
), checks_to_update AS (
    SELECT c.id FROM running_scans rs JOIN checks c
    ON c.parent_id=rs.id
    WHERE  c.data->>'status' IN (
        'MALFORMED', 'ABORTED', 'KILLED', 'FAILED', 'FINISHED', 'TIMEOUT', 'INCONCLUSIVE')
), checks_updated AS (
    UPDATE checks SET data = data || '{"check_added":true}'
    FROM  checks_to_update
    WHERE checks_to_update.id = checks.id
    RETURNING checks.id as id, checks.parent_id as scan_id
), finished_checks_per_scan AS (
    SELECT  scan_id, count(*) as checks_finished FROM checks_updated 
    GROUP BY scan_id
)
UPDATE scans s
SET data=(s.data || ('{"checks_finished": ' ||  COALESCE(f.checks_finished,0)|| '}')::jsonb)
FROM finished_checks_per_scan f
WHERE s.id=f.scan_id
