#!/usr/bin/env bash

# Copyright 2021 Adevinta

docker run --name vulcan-scan-enginedb -p 5434:5434 -e POSTGRES_PASSWORD=vulcan -e POSTGRES_USER=vulcan -e POSTGRES_DB=scan-enginedb -e PGPORT=5434 -d --rm postgres:13.3-alpine

while ! nc -z localhost 5434; do echo "Waiting for postgres" && sleep 2; done;
