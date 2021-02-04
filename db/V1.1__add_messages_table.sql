
CREATE TABLE messages (
    id serial,
    data jsonb,
    created_at timestamp with time zone not null DEFAULT NOW(),
    PRIMARY KEY(id)
);
