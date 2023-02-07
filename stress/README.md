# Stress test

k6 allows to execute test accessing the sql databases.

We can use this to easily prototype solutions/improvements and see the impact on
performance.

## Install k6 with sql support

See <https://github.com/grafana/xk6-sql>

Build a local xk6 with the sql module.

```sh
go install go.k6.io/xk6/cmd/xk6@latest
CGO_ENABLED=1 xk6 build --with github.com/grafana/xk6-sql
```

Start a local postgres

```sh
docker run -d -p 5432:5432 -e POSTGRES_PASSWORD=password postgres:13-alpine
```

Execute the performance test on the local db

```sh
./k6 run scan.js
```

Look for the available customizations in the script.

In this case set the connection string.
**Careful the test drops the existing `scans` and `checks` tables.**

```sh
./k6 run scan.js -e 'CONN_STR=postgres://postgres:password@localhost/postgres?sslmode=disable'
```

In this case execute `checks.js` 10000 times with 20 VUs.

```sh
./k6 run checks.js -u 20 -i 10000
```
