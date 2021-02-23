# vulcan-scan-engine
Component that allows to run, monitor and query the status of a scan.

The the component exposes endpoints:

1. [POST] /v1/scans

    Creates a new scan. See [swagger spec](https://github.com/adevinta/vulcan-scan-engine/blob/master/specs/scan-engine.swagger.yml).

2. [GET] /v1/scans/{scan_id}

    Gets the status of a scan.
    See [swagger spec](https://github.com/adevinta/vulcan-scan-engine/blob/master/specs/scan-engine.swagger.yml).

3. [GET] /v1/scans/?external_id={id}

    Gets a list of scans with given external id values.
    The endpoint will return only the last five created scans for the given external id
    unless the following query string param is added : &all=true .
    See [swagger spec](https://github.com/adevinta/vulcan-scan-engine/blob/master/specs/scan-engine.swagger.yml).

4. [POST] /v1/scans/{scan_id}/abort

   Aborts a scan.
   See [swagger spec](https://github.com/adevinta/vulcan-scan-engine/blob/master/specs/scan-engine.swagger.yml).

For running the component locally, clone and run at the root of the repo the following:

```
go install ./...
source db/postgres-start.sh
vulcan-scan-engine -c ../_resources/config/local.toml
```
# Docker execute

Those are the variables you have to use:

|Variable|Description|Sample|
|---|---|---|
|PORT||8081|
|LOG_LEVEL||error|
|PG_HOST||localhost|
|PG_NAME||scan-enginedb|
|PG_USER||vulcan|
|PG_PASSWORD||vulcan|
|PG_PORT||5432|
|PG_SSLMODE|One of these (disable,allow,prefer,require,verify-ca,verify-full)|disable|
|PG_CA_B64|A base64 encoded ca certificate||
|PERSISTENCE_HOST||persistence.vulcan.com|
|SQS_QUEUE_ARN||arn:aws:sqs:xxx:123456789012:yyy|
|AWS_SQS_ENDPOINT|Optional|http://custom-aws-endpoint|
|SNS_TOPIC_ARN||arn:aws:sns:xxx:123456789012:yyy|
|AWS_SNS_ENDPOINT|Optional|http://custom-aws-endpoint|

```bash
docker build . -t vse

# Use the default config.toml customized with env variables.
docker run --env-file ./local.env vse

# Use custom config.toml
docker run -v `pwd`/custom.toml:/app/config.toml vse
```
