
DROP INDEX exernal_id_index;
CREATE INDEX exernal_id_index ON scans ((data -> 'external_id'));
