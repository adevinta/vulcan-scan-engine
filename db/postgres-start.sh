#!/usr/bin/env bash

# Copyright 2021 Adevinta

docker run -q --name vulcan-scan-enginedb -p 5434:5434 -e POSTGRES_PASSWORD=vulcan -e POSTGRES_USER=vulcan -e POSTGRES_DB=scan-enginedb -e PGPORT=5434 -d --rm postgres:13.3-alpine

sleep 5

while ! docker exec vulcan-scan-enginedb pg_isready; do echo "Waiting for postgres" && sleep 2; done;
