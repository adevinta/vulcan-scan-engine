import crypto from 'k6/crypto';
import sql from 'k6/x/sql';
import http from 'k6/http';
import { uuidv4 } from 'https://jslib.k6.io/k6-utils/1.4.0/index.js';

const CONN_STR = __ENV.CONN_STR || "postgres://postgres:password@localhost/postgres?sslmode=disable";
const CHECKTYPES_URL=  __ENV.CHECKTYPES_URL || "https://adevinta.github.io/vulcan-checks/checktypes/edge.json";
const NUM_SCANS = __ENV.NUM_SCANS || 2
const NUM_TARGET_GROUPS = __ENV.NUM_TARGET_GROUPS || 2
const NUM_TARGETS = __ENV.NUM_TARGETS || 100
const CHECKPOINT = __ENV.CHECKPOINT || 100

const db = sql.open('postgres', CONN_STR);

export function setup() {
  db.exec(`
CREATE EXTENSION IF NOT EXISTS pgcrypto;
DROP TABLE IF EXISTS scans;
CREATE TABLE IF NOT EXISTS scans
(
    id text NOT NULL DEFAULT 'public.gen_random_uuid()',
    data jsonb NOT NULL,
    created_at timestamp with time zone NOT NULL DEFAULT 'now()',
    updated_at timestamp with time zone,
    CONSTRAINT scans_pkey PRIMARY KEY (id)
);

CREATE INDEX IF NOT EXISTS exernal_id_index
    ON scans USING btree
    ((data -> 'external_id'::text) ASC NULLS LAST);

DROP TABLE IF EXISTS checks;
CREATE TABLE IF NOT EXISTS checks
(
    id text NOT NULL DEFAULT 'public.gen_random_uuid()',
    parent_id text NOT NULL,
    data jsonb,
    created_at timestamp with time zone NOT NULL DEFAULT 'now()',
    updated_at timestamp with time zone,
    parent_index text COLLATE pg_catalog."default",
    CONSTRAINT checks_pkey PRIMARY KEY (parent_id, id)
);

CREATE UNIQUE INDEX IF NOT EXISTS checks_key
    ON checks USING btree
    (id ASC NULLS LAST)
    TABLESPACE pg_default;

CREATE INDEX IF NOT EXISTS checkstatus
    ON checks USING btree
    (parent_id ASC NULLS LAST, (data -> 'status'::text) ASC NULLS LAST)
    TABLESPACE pg_default;

CREATE UNIQUE INDEX IF NOT EXISTS scans_checks
    ON checks USING btree
    (parent_id ASC NULLS LAST, parent_index COLLATE pg_catalog."default" ASC NULLS LAST)
    TABLESPACE pg_default;
`
  )

  const res = http.get(CHECKTYPES_URL);
  const checkTypes = JSON.parse(res.body).checktypes

  const ctg = { name: "ctg", checktypes: checkTypes }
  for (let s = 0; s < NUM_SCANS; s++) {
    const uuid = uuidv4();
    const scan = { id: `${uuid}`, TargetGroups: [], ctg: ctg, check_count: NUM_TARGET_GROUPS * NUM_TARGETS, checks_created: 0, status: "RUNNING" }
    for (let tg = 0; tg < NUM_TARGET_GROUPS; tg++) {
      let targets = []
      for (let a = 0; a < NUM_TARGETS; a++) {
        targets.push({ identifier: `tg${tg}-asset${a}`, type: "Hostname" })
      }
      scan.TargetGroups.push({ name: `target${tg}`, targets: targets, options: {}, ctg: ctg })
    }
    db.exec('insert into scans(id, data) values($1, $2)', scan.id, JSON.stringify(scan));
  }
}

function GetCreatingScans() {
  return sql.query(db, `
  select id from scans
  where (
      data->'checks_created' is not null
      AND data->'check_count' <> data->'checks_created'
      AND data->>'status' = 'RUNNING'
  )`
  )
}

function InsertChildDocIfNotExists(table, parentId, childId, index, data) {
  const check = sql.query(db, `
  WITH q as (
    SELECT * FROM ${table}
	WHERE parent_id = $1 and parent_index = $2
	),
	c AS (
      INSERT INTO ${table} (id, parent_id, parent_index, data, created_at, updated_at)
      SELECT $4, $1, $2, $3, NOW(), NOW()
      WHERE NOT EXISTS (SELECT 1 FROM q)
      RETURNING *
    )
    SELECT id::text FROM c
    UNION ALL
	SELECT id::text FROM q
  `, parentId, index, JSON.stringify(data), childId)

  if (check.length > 0) {
    return check[0].id
  }
}

function InsertCheckIfNotExists(c) {
  return InsertChildDocIfNotExists("checks", c.scan_index, c.id, c.scan_index, c)
}

function CreateScanChecks(id) {
  console.log(`Creating scan ${id}`)

  const scan = GetScanByID(id)
  if (!scan) {
    console.error(`Scan ${id} not found`)
    return
  }

  let checks_created = 0
  for (let tgi = 0; tgi < scan.TargetGroups.length; tgi++) {
    const tg = scan.TargetGroups[tgi];
    let checkGroupIndex = -1
    for (let cgi = 0; cgi < tg.targets.length; cgi++) {
      const target = tg.targets[cgi]
      for (const ct of tg.ctg.checktypes) {
        checkGroupIndex++
        let index = `${tgi}-${checkGroupIndex}`
        const uuid = uuidv4();
        const check = {
          scan_index: index,
          id: `${uuid}`,
          status: "CREATED",
          scan_id: scan.id,
          target: target.identifier,
          progress: 0.0,
          checktype_id: ct.name,
          checktype_name: ct.name,
          image: ct.image,
          options: ct.options,
          assettype: target.type,
          required_vars: ct.RequiredVars,
          created_at: Date.now(),
          updated_at: Date.now(),
          timeout: ct.timeout
        }
        InsertCheckIfNotExists(check)
        checks_created++

        if (checks_created % CHECKPOINT == 0) {
          const update = {
            ID: scan.id,
            checks_created: checks_created,
            last_target_check_g_created: tgi,
            last_check_created: checkGroupIndex
          };
          UpsertDocWithCondition("scans", scan.id, update, "")
        }
      }
    }
  }
  console.log(`Scan created id:${id} checks:${checks_created}`)
  db.exec(`update scans set data= data || $1 where id=$2`, JSON.stringify({ status: "FINISHED" }), id)
}


function UpsertDocWithCondition(table, id, data, condition) {
  let st = `INSERT INTO ${table} VALUES ($1,$2,now(),now())
  ON CONFLICT ON CONSTRAINT ${table}_pkey
  DO UPDATE SET data = ${table}.data || $2, updated_at = now()`
  if (condition != "") {
    st = st + ` WHERE ${condition} `
  }
  return sql.query(db, st, id, JSON.stringify(data))
}

function GetScanByID(id) {
  const res = sql.query(db, `select data::text from scans where id=$1`, id)
  if (res.length == 1) {
    return JSON.parse(res[0].data)
  }
}

export function teardown() {
  // Keep the tables to allow inspecting the results.
  // db.exec(`DROP TABLE scans; DROP TABLE checks;`);
  // db.close();
}

export default function () {
  let scans = GetCreatingScans()
  while (scans.length > 0) {
    CreateScanChecks(scans[0].id)
    scans = GetCreatingScans()
  }
}
