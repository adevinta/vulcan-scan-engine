WITH running_scans AS (
    SELECT id FROM scans where data->>'status' = 'RUNNING' AND EXTRACT(MONTH from created_at) = 4
    AND EXTRACT(YEAR FROM created_at) = 2021 AND data->>'check_count' IS NOT NULL
),finished_checks_per_scan AS (
    SELECT parent_id as scan_id, count(*) as checks_finished FROM checks c JOIN running_scans rs
    ON c.parent_id=rs.id
    WHERE  c.data->>'status' IN (
        'MALFORMED', 'ABORTED', 'KILLED', 'FAILED', 'FINISHED', 'TIMEOUT', 'INCONCLUSIVE'
    )
    GROUP BY parent_id
) 
UPDATE scans s
SET data=(data || ('{"checks_finished": ' || ((f.checks_finished)::int + 1) || '}')::jsonb)
FROM finished_checks_per_scan f WHERE s.id=f.scan_id


/*SELECT parent_id as scan_id, count(*) as checks_finished FROM checks c 
    WHERE  parent_id='61b20518-5d45-42fc-b007-12866d1c323a' and c.data->>'status' IN (
        'MALFORMED', 'ABORTED', 'KILLED', 'FAILED', 'FINISHED', 'TIMEOUT', 'INCONCLUSIVE'
    )*/
