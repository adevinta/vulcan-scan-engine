#!/bin/sh

# Copyright 2021 Adevinta

# export default values for required vars if not set
export PORT=${PORT:-8080}
export DOGSTATSD_ENABLED=${DOGSTATSD_ENABLED:-false}
export CHECKS_SQS_PROCESSORS=${CHECKS_SQS_PROCESSORS:-8}
export CHECKS_SQS_INTERVAL=${CHECKS_SQS_INTERVAL:-10}
export CHECKS_SQS_WAIT=${CHECKS_SQS_WAIT:-20}
export CHECS_SQS_TIMEOUT=${CHECS_SQS_TIMEOUT:-30}


# Apply env variables
cat config.toml | envsubst > run.toml

if [ ! -z "$PG_CA_B64" ]; then
  mkdir /root/.postgresql
  echo $PG_CA_B64 | base64 -d > /root/.postgresql/root.crt   # for flyway
  echo $PG_CA_B64 | base64 -d > /etc/ssl/certs/pg.crt  # for vulcan-api
fi

flyway -user=$PG_USER -password=$PG_PASSWORD \
  -url=jdbc:postgresql://$PG_HOST:$PG_PORT/$PG_NAME?sslmode=$PG_SSLMODE \
  -baselineOnMigrate=true -locations=filesystem:/app/sql migrate

./vulcan-scan-engine -c run.toml
