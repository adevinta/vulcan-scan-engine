#!/usr/bin/env bash

# Copyright 2021 Adevinta

docker run --net=host -v $(pwd):/scripts boxfuse/flyway -user=vulcan -password=vulcan -url=jdbc:postgresql://localhost:5434/scan-enginedb -baselineOnMigrate=true -locations=filesystem:/scripts/ repair
