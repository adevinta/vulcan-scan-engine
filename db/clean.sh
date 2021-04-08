#!/usr/bin/env bash

# Copyright 2021 Adevinta

docker run --net=host --rm -v $(pwd):/flyway/sql flyway/flyway:${FLYWAY_VERSION:-7} -user=vulcan -password=vulcan -url=jdbc:postgresql://localhost:5434/scan-enginedb -baselineOnMigrate=true clean