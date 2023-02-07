import { check } from 'k6';
import sql from 'k6/x/sql';

const CONN_STR = __ENV.CONN_STR || "postgres://postgres:password@localhost/postgres?sslmode=disable";

const db = sql.open('postgres', CONN_STR);

export function setup() {
  db.exec(`
CREATE EXTENSION IF NOT EXISTS pgcrypto;

DROP TABLE IF EXISTS checks;

CREATE TABLE IF NOT EXISTS public.checks
(
    id text NOT NULL DEFAULT public.gen_random_uuid(),
    parent_id text NOT NULL,
    data jsonb,
    created_at timestamp with time zone NOT NULL DEFAULT 'now()',
    updated_at timestamp with time zone,
    parent_index text COLLATE pg_catalog."default",
    CONSTRAINT checks_pkey PRIMARY KEY (parent_id, id)
);

CREATE UNIQUE INDEX IF NOT EXISTS checks_key
    ON public.checks USING btree
    (id ASC NULLS LAST)
    TABLESPACE pg_default;

CREATE INDEX IF NOT EXISTS checkstatus
    ON public.checks
    (parent_id ASC NULLS LAST, (data -> 'status'::text) ASC NULLS LAST)
    TABLESPACE pg_default;

CREATE UNIQUE INDEX IF NOT EXISTS scans_checks
    ON public.checks USING btree
    (parent_id ASC NULLS LAST, parent_index COLLATE pg_catalog."default" ASC NULLS LAST)
    TABLESPACE pg_default;
`
)
}

export function teardown() {
  // Keep the tables to allow inspecting the results.
  // db.exec(`DROP TABLE checks;`);
  // db.close();
}

const data= `{
  "id": "0a90434c-2796-417a-88ef-48d58447c398",
  "image": "vulcansec/vulcan-certinfo:edge",
  "status": "CREATED",
  "target": "tg0-asset0",
  "scan_id": "3d4ccbc0-2a51-4cda-bbef-1166c17df5c1",
  "timeout": 60,
  "progress": 0,
  "assettype": "Hostname",
  "created_at": 1675753202759,
  "scan_index": "0-4",
  "updated_at": 1675753202759,
  "checktype_id": "vulcan-certinfo",
  "checktype_name": "vulcan-certinfo"
}`;

export default function () {
  db.exec('insert into checks(parent_id, data, parent_index) values ($1,$2,$3)', __VU, data, `${__VU}-${__ITER}}`)
  let res=sql.query(db, `select id from checks where parent_id=$1 and parent_index=$2`, __VU, `${__VU}-${__ITER}}`)
  check(res, {
    'found': (r) => r.length==1
  });
  res=sql.query(db, `select count(*) n from checks where parent_id=$1 and data->>'status'=$2`, __VU, 'CREATED')
  check(res, {
    'count ok': (r) => r.length==1 && r[0].n > 0
  });
}
