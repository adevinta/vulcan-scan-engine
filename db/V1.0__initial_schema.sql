CREATE EXTENSION IF NOT EXISTS pgcrypto;

 CREATE TABLE scans (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    data jsonb not null,
    created_at timestamp with time zone not null DEFAULT NOW(),
    updated_at timestamp with time zone
);

 CREATE TABLE checks (
     id UUID DEFAULT gen_random_uuid(),
    parent_id UUID ,
    data jsonb,
    created_at timestamp with time zone not null DEFAULT NOW(),
    updated_at timestamp with time zone,
    PRIMARY KEY(parent_id,id)
);
