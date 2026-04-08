FROM golang:alpine AS build
ARG VERSION=dev
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY main.go .
COPY static/ static/
RUN CGO_ENABLED=0 go build -ldflags="-s -w -X main.version=${VERSION}" -o maxmux .

FROM alpine
COPY --from=build /app/maxmux /usr/local/bin/maxmux
RUN mkdir -p /data
VOLUME ["/data"]
ENTRYPOINT ["maxmux"]
