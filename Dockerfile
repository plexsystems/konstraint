FROM golang:1.14-alpine AS build
WORKDIR /go/src/github.com/plexsystems/konstraint
COPY go.mod .
COPY go.sum .
RUN go mod download
COPY main.go .
COPY internal/ internal
ARG KONSTRAINT_VER
RUN go build -o /konstraint  -ldflags="-X 'github.com/plexsystems/konstraint/internal/commands.version=${KONSTRAINT_VER}'"

FROM alpine:3.12
COPY --from=build /konstraint /usr/bin/konstraint
ENTRYPOINT ["konstraint"]