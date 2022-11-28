# Copyright 2021 Adevinta

FROM golang:1.19.3-alpine3.15 as builder

WORKDIR /app

COPY go.mod .
COPY go.sum .

RUN go mod download

COPY . .

RUN cd cmd/vulcan-scan-engine/ && GOOS=linux GOARCH=amd64 go build . && cd -

FROM alpine:3.17.0

WORKDIR /flyway

RUN apk add --no-cache --update openjdk8-jre-base bash gettext

ARG FLYWAY_VERSION=9.4.0

RUN wget https://repo1.maven.org/maven2/org/flywaydb/flyway-commandline/${FLYWAY_VERSION}/flyway-commandline-${FLYWAY_VERSION}.tar.gz \
    && tar -xzf flyway-commandline-${FLYWAY_VERSION}.tar.gz --strip 1 \
    && rm flyway-commandline-${FLYWAY_VERSION}.tar.gz \
    && find ./drivers/ -type f -not -name 'postgres*' -delete \
    && chown -R root:root . \
    && ln -s /flyway/flyway /bin/flyway

WORKDIR /app

ARG BUILD_RFC3339="1970-01-01T00:00:00Z"
ARG COMMIT="local"

ENV BUILD_RFC3339 "$BUILD_RFC3339"
ENV COMMIT "$COMMIT"

COPY db/*.sql /app/sql/

COPY --from=builder /app/cmd/vulcan-scan-engine/vulcan-scan-engine .

COPY config.toml .
COPY run.sh .

CMD [ "./run.sh" ]
