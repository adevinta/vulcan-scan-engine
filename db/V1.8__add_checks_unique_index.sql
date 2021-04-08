DROP INDEX scans_checks;
CREATE INDEX scans_checks ON checks (parent_id, parent_index);
