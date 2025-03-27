#!/usr/bin/env bash

# Copyright 2021 Adevinta

docker run -q --net=host --rm -v "$PWD":/flyway/sql flyway/flyway:"${FLYWAY_VERSION:-10}-alpine" \
    -user=vulcan -password=vulcan -url=jdbc:postgresql://localhost:5434/scan-enginedb -baselineOnMigrate=true migrate
