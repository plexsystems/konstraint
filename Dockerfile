FROM golang:1.19.5-alpine AS build
ARG KONSTRAINT_VER

WORKDIR /go/src/github.com/plexsystems/konstraint

COPY go.mod .
COPY go.sum .
RUN go mod download

COPY main.go .
COPY internal/ internal

RUN go build -o /konstraint -ldflags="-X 'github.com/plexsystems/konstraint/internal/commands.version=${KONSTRAINT_VER}'"

FROM alpine:3.17.2
COPY --from=build /konstraint /usr/bin/konstraint
ENTRYPOINT ["konstraint"]
