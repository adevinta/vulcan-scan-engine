#!/bin/bash

# Copyright 2021 Adevinta

# export default values for required vars if not set
export PORT=${PORT:-8080}
export DOGSTATSD_ENABLED=${DOGSTATSD_ENABLED:-false}
export CHECKS_SQS_PROCESSORS=${CHECKS_SQS_PROCESSORS:-8}
export CHECKS_SQS_INTERVAL=${CHECKS_SQS_INTERVAL:-10}
export CHECKS_SQS_WAIT=${CHECKS_SQS_WAIT:-20}
export CHECKS_SQS_TIMEOUT=${CHECKS_SQS_TIMEOUT:-30}
export CHECKS_CREATOR_CHECKPOINT=${CHECKS_CREATOR_CHECKPOINT:-100}
export PERSISTENCE_CACHE=${PERSISTENCE_CACHE:-120}

# Nessus section  will be deprecated, 
# We add this for compatibility using the new dynamic method.
export QUEUES_NESSUS_CHECKTYPES=${QUEUES_NESSUS_CHECKTYPES:-'[]'}

# Apply env variables
envsubst < config.toml > run.toml

# Add dynamic queue configs
i=1 VARN="QUEUES_${i}_ARN"
while [ -n "${!VARN}" ]
do
  VCT="QUEUES_${i}_CHECKTYPES"
  echo "
    [queues.q$i]
    arn = \"${!VARN}\"
    checktypes = ${!VCT}
" >> run.toml
  i=$((i+1))
  VARN="QUEUES_${i}_ARN" VCT="QUEUES_${i}_CHECKTYPES"
done

if [ -n "$PG_CA_B64" ]; then
  mkdir /root/.postgresql
  echo $PG_CA_B64 | base64 -d > /root/.postgresql/root.crt   # for flyway
  echo $PG_CA_B64 | base64 -d > /etc/ssl/certs/pg.crt  # for vulcan-api
fi

flyway -user="$PG_USER" -password="$PG_PASSWORD" \
  -url="jdbc:postgresql://$PG_HOST:$PG_PORT/$PG_NAME?sslmode=$PG_SSLMODE" \
  -community -baselineOnMigrate=true -locations=filesystem:/app/sql migrate

exec ./vulcan-scan-engine -c run.toml
