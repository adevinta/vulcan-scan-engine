
CREATE INDEX "checkstatus" on "checks" (parent_id,(data->'status'));
