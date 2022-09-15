#!/usr/bin/env bash

# Copyright 2021 Adevinta

docker run --net=host --rm -v "$PWD":/flyway/sql flyway/flyway:"${FLYWAY_VERSION:-9}-alpine" \
    -user=vulcan -password=vulcan -url=jdbc:postgresql://localhost:5434/scan-enginedb -baselineOnMigrate=true -cleanDisabled=false clean
