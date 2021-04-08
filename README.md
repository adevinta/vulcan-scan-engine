# vulcan-scan-engine
Component that allows to run, monitor and query the status of a scan.

The the component exposes endpoints:

1. [POST] /v1/scans

    Creates a new scan. See [swagger spec](https://github.com/adevinta/vulcan-scan-engine/blob/master/specs/scan-engine.swagger.yml).

2. [GET] /v1/scans/{scan_id}

    Gets the status of a scan.
    See [swagger spec](https://github.com/adevinta/vulcan-scan-engine/blob/master/specs/scan-engine.swagger.yml).

3. [GET] /v1/scans?external_id={id}&offset={offset}&limit={limit}
    
    Gets the list of scans ordered by descending creation time.
    External ID param is optional, if set lists only the scans for that external ID.
    Offset and limit parameters are optional, if not set, all results are returned.
    See [swagger spec](https://github.com/adevinta/vulcan-scan-engine/blob/master/specs/scan-engine.swagger.yml).

4. [GET] /v1/scans/{scan_id}/checks

    Gets the checks for a scan.
    See [swagger spec](https://github.com/adevinta/vulcan-scan-engine/blob/master/specs/scan-engine.swagger.yml).

5. [GET] /v1/scans/{scan_id}/stats

    Gets the check stats for a scan.
    See [swagger spec](https://github.com/adevinta/vulcan-scan-engine/blob/master/specs/scan-engine.swagger.yml).

6. [POST] /v1/scans/{scan_id}/abort

   Aborts a scan.
   See [swagger spec](https://github.com/adevinta/vulcan-scan-engine/blob/master/specs/scan-engine.swagger.yml).

7. [GET] /v1/checks/{check_id}

   Gets a check by its ID.
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
|CHECKS_SQS_ARN|ARN for the checks creation queue|arn:aws:sqs:xxx:123456789012:yyy|
|CHECKS_SQS_ENDPOINT|Endpoint for the checks creation queue (optional)|http://custom-aws-endpoint|
|CHECKS_SQS_PROCESSORS|Number of workers processing check updates|8|
|CHECKS_SQS_INTERVAL||10|
|CHECKS_SQS_WAIT||20|
|CHECKS_SQS_TIMEOUT||30|
|SCANS_SNS_ARN|ARN for the scans notification topic|arn:aws:sns:xxx:123456789012:yyy|
|SCANS_SNS_ENDPOINT|Endpoint for the scans notification topic (optional)|http://custom-aws-endpoint|
|CHECKS_SNS_ARN|ARN for the checks status notification topic|arn:aws:sns:xxx:123456789012:yyy|
|CHECKS_SNS_ENDPOINT|Endpoint for the checks status notification topic (optional)|http://custom-aws-endpoint|
|CHECKS_CREATOR_WORKERS|Number of workers to run for checks creation||
|CHECKS_CREATOR_PERIOD|Period (seconds) for which workers should look for checks pending to be created||
|QUEUES_DEFAULT_ARN|Default checks queue ARN|arn:aws:sqs:xxx:123456789012:yyy|
|QUEUES_NESSUS_ARN|Nessus checks ARN|arn:aws:sqs:xxx:123456789012:yyy|
|QUEUES_NESSUS_CHECKTYPES|List of checks to create in nessus queue|["vulcan-nessus"]|

```bash
docker build . -t vse

# Use the default config.toml customized with env variables.
docker run --env-file ./local.env vse

# Use custom config.toml
docker run -v `pwd`/custom.toml:/app/config.toml vse
```
