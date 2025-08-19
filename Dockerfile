# Copyright 2021 Adevinta

FROM --platform=$BUILDPLATFORM golang:1.25-alpine AS builder

WORKDIR /app

COPY go.mod go.sum ./

RUN go mod download

COPY . .

ARG TARGETOS TARGETARCH

RUN GOOS=$TARGETOS GOARCH=$TARGETARCH go build ./cmd/vulcan-scan-engine

FROM alpine:3.22

WORKDIR /flyway

RUN apk add --no-cache openjdk17-jre bash gettext

ARG FLYWAY_VERSION=10.10.0

RUN wget -q https://repo1.maven.org/maven2/org/flywaydb/flyway-commandline/${FLYWAY_VERSION}/flyway-commandline-${FLYWAY_VERSION}.tar.gz \
    && tar -xzf flyway-commandline-${FLYWAY_VERSION}.tar.gz --strip 1 \
    && rm flyway-commandline-${FLYWAY_VERSION}.tar.gz \
    && find ./drivers/ -type f -not -name '*postgres*' -not -name '*jackson*' -delete \
    && chown -R root:root . \
    && ln -s /flyway/flyway /bin/flyway

WORKDIR /app

COPY --link db/*.sql ./sql/
COPY --link config.toml run.sh ./

COPY --from=builder --link /app/vulcan-scan-engine .

CMD [ "./run.sh" ]
