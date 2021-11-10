FROM golang:1.17-alpine as backend
ENV CGO_ENABLED=0

ADD . /build
WORKDIR /build

RUN apk add --no-cache --update git tzdata ca-certificates
RUN go build -o /build/secretable -ldflags "-s -w" /build/cmd/secretable.go

FROM alpine
RUN mkdir /etc/secretable
COPY --from=backend /build/secretable /srv/secretable

WORKDIR /srv
ENTRYPOINT ["/srv/secretable", "-c", "/etc/secretable/config.yaml"]