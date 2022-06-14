FROM golang:1.18.3-alpine AS build
ARG KONSTRAINT_VER

WORKDIR /go/src/github.com/plexsystems/konstraint

COPY go.mod .
COPY go.sum .
RUN go mod download

COPY main.go .
COPY internal/ internal

RUN go build -o /konstraint -ldflags="-X 'github.com/plexsystems/konstraint/internal/commands.version=${KONSTRAINT_VER}'"

FROM alpine:3.16.0
COPY --from=build /konstraint /usr/bin/konstraint
ENTRYPOINT ["konstraint"]
