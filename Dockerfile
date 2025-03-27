# Copyright 2021 Adevinta

FROM --platform=linux/$TARGETARCH golang:1.24-alpine AS builder

WORKDIR /app

COPY go.mod go.sum ./

RUN go mod download

COPY . .

ARG TARGETOS TARGETARCH

WORKDIR /app/cmd/vulcan-scan-engine
RUN GOOS=$TARGETOS GOARCH=$TARGETARCH go build .

FROM alpine:3.21

WORKDIR /flyway

RUN apk add --no-cache --update openjdk17-jre bash gettext

ARG FLYWAY_VERSION=10.10.0

RUN wget -q https://repo1.maven.org/maven2/org/flywaydb/flyway-commandline/${FLYWAY_VERSION}/flyway-commandline-${FLYWAY_VERSION}.tar.gz \
    && tar -xzf flyway-commandline-${FLYWAY_VERSION}.tar.gz --strip 1 \
    && rm flyway-commandline-${FLYWAY_VERSION}.tar.gz \
    && find ./drivers/ -type f | grep -Ev '(postgres|jackson)' | xargs rm \
    && chown -R root:root . \
    && ln -s /flyway/flyway /bin/flyway

WORKDIR /app

COPY --link db/*.sql ./sql/
COPY --link config.toml run.sh ./

COPY --from=builder --link /app/cmd/vulcan-scan-engine/vulcan-scan-engine .

CMD [ "./run.sh" ]
